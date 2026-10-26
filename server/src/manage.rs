//! Server management operations shared by the TUI (`ssm-server tui`) and the
//! Admin API. Every change is audited with the acting admin (none for the
//! TUI, which runs on the server host) and its origin.

use chrono::{DateTime, Local, Utc};
use sqlx::Row;
use ssm_proto::B64;
use ssm_proto::api::{DeviceAction, DeviceStatus};
use uuid::Uuid;

use crate::audit::{self, Entry};
use crate::conversations::{self, NewJob};
use crate::devices::{self, ActionOutcome};
use crate::{AppState, accounts, massdelete};

pub type DataResult<T> = Result<T, String>;

fn db(err: sqlx::Error) -> String {
    format!("database error: {err}")
}

pub fn local_time(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string()
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub accounts: i64,
    pub admins: i64,
    pub devices_pending: i64,
    pub devices_active: i64,
    pub devices_disabled: i64,
    pub conversations: i64,
    pub messages: i64,
    pub jobs_running: i64,
    pub jobs_backup_pending: i64,
    pub audit_entries: i64,
}

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: Uuid,
    pub username: String,
    pub name: String,
    pub status: DeviceStatus,
    pub created: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub status: String,
    pub created: String,
    pub active_devices: i64,
    pub messages: i64,
}

#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: Uuid,
    pub scope: String,
    pub status: String,
    pub affected: i64,
    pub created: String,
    pub backup_due: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub id: i64,
    pub time: String,
    pub action: String,
    pub target: String,
    pub result: String,
}

pub async fn stats(state: &AppState) -> DataResult<Stats> {
    let row = sqlx::query(
        "SELECT
            (SELECT count(*) FROM accounts) AS accounts,
            (SELECT count(*) FROM accounts WHERE role = 'admin') AS admins,
            (SELECT count(*) FROM devices WHERE status = 'pending') AS pending,
            (SELECT count(*) FROM devices WHERE status = 'active') AS active,
            (SELECT count(*) FROM devices WHERE status = 'disabled') AS disabled,
            (SELECT count(*) FROM conversations) AS conversations,
            (SELECT count(*) FROM messages WHERE kind = 'encrypted' AND deleted_at IS NULL AND expires_at > now()) AS messages,
            (SELECT count(*) FROM delete_jobs WHERE status IN ('requested', 'in_progress')) AS jobs_running,
            (SELECT count(*) FROM delete_jobs WHERE status = 'backup_purge_pending') AS jobs_backup,
            (SELECT count(*) FROM admin_audit_events) AS audit",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(db)?;
    let get = |name: &str| row.try_get::<i64, _>(name).unwrap_or_default();
    Ok(Stats {
        accounts: get("accounts"),
        admins: get("admins"),
        devices_pending: get("pending"),
        devices_active: get("active"),
        devices_disabled: get("disabled"),
        conversations: get("conversations"),
        messages: get("messages"),
        jobs_running: get("jobs_running"),
        jobs_backup_pending: get("jobs_backup"),
        audit_entries: get("audit"),
    })
}

/// Pending devices first, then newest first.
pub async fn devices(state: &AppState, filter: Option<DeviceStatus>) -> DataResult<Vec<DeviceRow>> {
    let rows = sqlx::query(
        "SELECT d.id, a.username, d.display_name, d.status, d.created_at, d.olm_fingerprint_key
         FROM devices d JOIN accounts a ON a.id = d.account_id
         WHERE $1::text IS NULL OR d.status = $1
         ORDER BY d.status = 'pending' DESC, d.created_at DESC",
    )
    .bind(filter.map(DeviceStatus::as_str))
    .fetch_all(&state.pool)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            let fingerprint = B64::encode(&row.try_get::<Vec<u8>, _>("olm_fingerprint_key").map_err(db)?);
            Ok(DeviceRow {
                id: row.try_get("id").map_err(db)?,
                username: row.try_get("username").map_err(db)?,
                name: row.try_get("display_name").map_err(db)?,
                status: DeviceStatus::parse(row.try_get("status").map_err(db)?).ok_or("unknown status")?,
                created: local_time(row.try_get("created_at").map_err(db)?),
                fingerprint: fingerprint
                    .as_bytes()
                    .chunks(4)
                    .map(|c| String::from_utf8_lossy(c).into_owned())
                    .collect::<Vec<_>>()
                    .join(" "),
            })
        })
        .collect()
}

pub async fn accounts(state: &AppState) -> DataResult<Vec<AccountRow>> {
    let rows = sqlx::query(
        "SELECT a.id, a.username, a.role, a.status, a.created_at,
                (SELECT count(*) FROM devices d WHERE d.account_id = a.id AND d.status = 'active') AS devices,
                (SELECT count(*) FROM messages m WHERE m.sender_account_id = a.id AND m.kind = 'encrypted'
                    AND m.deleted_at IS NULL AND m.expires_at > now()) AS messages
         FROM accounts a ORDER BY a.username",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            Ok(AccountRow {
                id: row.try_get("id").map_err(db)?,
                username: row.try_get("username").map_err(db)?,
                role: row.try_get("role").map_err(db)?,
                status: row.try_get("status").map_err(db)?,
                created: local_time(row.try_get("created_at").map_err(db)?),
                active_devices: row.try_get("devices").map_err(db)?,
                messages: row.try_get("messages").map_err(db)?,
            })
        })
        .collect()
}

pub async fn jobs(state: &AppState) -> DataResult<Vec<JobRow>> {
    let rows = sqlx::query(
        "SELECT j.id, j.scope, j.status, j.affected_messages, j.created_at, j.backup_purge_due_at, j.error_summary,
                j.requested_by_admin, a.username
         FROM delete_jobs j LEFT JOIN accounts a ON a.id = (j.scope->>'account_id')::uuid
         ORDER BY j.created_at DESC LIMIT 300",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            let scope: serde_json::Value = row.try_get("scope").map_err(db)?;
            let scope = match scope["type"].as_str() {
                Some("account") => format!(
                    "all content of {}",
                    row.try_get::<Option<String>, _>("username")
                        .map_err(db)?
                        .or_else(|| scope["username"].as_str().map(|u| format!("{u} (deleted)")))
                        .unwrap_or_else(|| "?".into())
                ),
                Some("message") => "one message".to_owned(),
                Some("replay") => "deletions replayed after a restore".to_owned(),
                other => other.unwrap_or("?").to_owned(),
            };
            Ok(JobRow {
                id: row.try_get("id").map_err(db)?,
                scope: if row.try_get("requested_by_admin").map_err(db)? { format!("{scope} (admin)") } else { scope },
                status: row.try_get("status").map_err(db)?,
                affected: row.try_get("affected_messages").map_err(db)?,
                created: local_time(row.try_get("created_at").map_err(db)?),
                backup_due: row
                    .try_get::<Option<DateTime<Utc>>, _>("backup_purge_due_at")
                    .map_err(db)?
                    .map(local_time)
                    .unwrap_or_default(),
                error: row.try_get::<Option<String>, _>("error_summary").map_err(db)?.unwrap_or_default(),
            })
        })
        .collect()
}

pub async fn audit(state: &AppState) -> DataResult<Vec<AuditRow>> {
    let rows = sqlx::query(
        "SELECT e.id, e.created_at, e.action, e.result,
                COALESCE('account ' || a.username,
                         'device ' || d.display_name || ' (' || da.username || ')',
                         e.target) AS target
         FROM admin_audit_events e
         LEFT JOIN accounts a ON e.target = 'account:' || a.id::text
         LEFT JOIN devices d ON e.target = 'device:' || d.id::text
         LEFT JOIN accounts da ON da.id = d.account_id
         ORDER BY e.id DESC LIMIT 500",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(db)?;
    rows.iter()
        .map(|row| {
            Ok(AuditRow {
                id: row.try_get("id").map_err(db)?,
                time: local_time(row.try_get("created_at").map_err(db)?),
                action: row.try_get("action").map_err(db)?,
                target: row.try_get("target").map_err(db)?,
                result: row.try_get("result").map_err(db)?,
            })
        })
        .collect()
}

pub async fn verify_audit(state: &AppState) -> DataResult<String> {
    match audit::verify_chain(&state.pool).await.map_err(db)? {
        Ok(count) => Ok(format!("Audit chain intact ({count} entries).")),
        Err(id) => Err(format!("AUDIT CHAIN BROKEN at entry {id} – the log was modified!")),
    }
}

/// Who performs an operation.
#[derive(Debug, Clone, Copy)]
pub struct Actor {
    pub admin_account_id: Option<Uuid>,
    /// Appended to audit results, e.g. " (tui)".
    pub origin: &'static str,
}

impl Actor {
    pub const TUI: Actor = Actor { admin_account_id: None, origin: " (tui)" };
    pub const CLI: Actor = Actor { admin_account_id: None, origin: " (cli)" };

    pub fn admin(account_id: Uuid) -> Self {
        Self { admin_account_id: Some(account_id), origin: "" }
    }

    fn ok(&self) -> String {
        format!("ok{}", self.origin)
    }
}

fn entry<'a>(actor: Actor, action: &'a str, target: &'a str, result: &'a str) -> Entry<'a> {
    Entry { admin_account_id: actor.admin_account_id, action, target, result, correlation_id: Uuid::new_v4() }
}

pub async fn device_action(
    state: &AppState,
    actor: Actor,
    device_id: Uuid,
    action: DeviceAction,
) -> DataResult<String> {
    let mut tx = state.pool.begin().await.map_err(db)?;
    let outcome =
        devices::apply_action(&mut tx, device_id, action, actor.admin_account_id, actor.origin).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    match outcome {
        ActionOutcome::Changed(next) => {
            if next != DeviceStatus::Active {
                state.close_device(device_id);
            }
            Ok(match next {
                DeviceStatus::Revoked | DeviceStatus::Rejected => format!("Device {} and deleted.", next.as_str()),
                _ => format!("Device is now {}.", next.as_str()),
            })
        }
        ActionOutcome::NotFound => Err("Device not found.".into()),
        ActionOutcome::InvalidTransition(current) => {
            Err(format!("Cannot {} a device that is {}.", action.as_str(), current.as_str()))
        }
    }
}

/// Creates a user account and returns its invite code.
pub async fn create_account(state: &AppState, actor: Actor, username: &str) -> DataResult<String> {
    if !accounts::is_valid_username(username) {
        return Err("Username must be 3-32 characters of a-z, 0-9, '_', '.', '-'.".into());
    }
    let mut tx = state.pool.begin().await.map_err(db)?;
    let account_id =
        accounts::create_account(&mut tx, username, "user").await.map_err(db)?.ok_or("Username is taken.")?;
    let (code, expires) = accounts::create_invite(&mut tx, account_id).await.map_err(db)?;
    audit::append(&mut tx, entry(actor, "account.create", &format!("account:{account_id}"), &actor.ok()))
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(format!("Account '{username}' created.\n\nInvite code:  {code}\nValid until:  {}", local_time(expires)))
}

pub async fn new_invite(state: &AppState, actor: Actor, account_id: Uuid, username: &str) -> DataResult<String> {
    let mut tx = state.pool.begin().await.map_err(db)?;
    let (code, expires) = accounts::create_invite(&mut tx, account_id).await.map_err(db)?;
    audit::append(&mut tx, entry(actor, "invite.create", &format!("account:{account_id}"), &actor.ok()))
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(format!(
        "New invite code for '{username}' (older unused codes are invalid now):\n\n{code}\nValid until:  {}",
        local_time(expires)
    ))
}

/// Disables or re-enables a whole account. Disabled accounts cannot use any
/// device; open connections are closed.
pub async fn set_account_status(state: &AppState, actor: Actor, account_id: Uuid, disable: bool) -> DataResult<String> {
    let status = if disable { "disabled" } else { "active" };
    let mut tx = state.pool.begin().await.map_err(db)?;
    let updated = sqlx::query("UPDATE accounts SET status = $2 WHERE id = $1 AND status <> $2")
        .bind(account_id)
        .bind(status)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if updated.rows_affected() == 0 {
        return Err(format!("Account is already {status}."));
    }
    let devices: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM devices WHERE account_id = $1")
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
    if disable {
        sqlx::query("DELETE FROM sessions WHERE device_id = ANY($1)")
            .bind(&devices)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
    }
    let action = if disable { "account.disable" } else { "account.enable" };
    audit::append(&mut tx, entry(actor, action, &format!("account:{account_id}"), &actor.ok())).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    if disable {
        devices.into_iter().for_each(|d| state.close_device(d));
    }
    Ok(format!("Account is now {status}."))
}

/// Starts the deletion of everything the account has sent, for everyone.
pub async fn start_mass_delete(state: &AppState, actor: Actor, account_id: Uuid) -> DataResult<String> {
    let job = NewJob {
        id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        requested_by: None,
        requested_by_admin: true,
        scope: serde_json::json!({ "type": "account", "account_id": account_id }),
    };
    let mut tx = state.pool.begin().await.map_err(db)?;
    conversations::insert_job(&mut tx, &job, ssm_proto::api::DeleteJobStatus::InProgress).await.map_err(db)?;
    audit::append(
        &mut tx,
        Entry {
            admin_account_id: actor.admin_account_id,
            action: "account.delete_all_content",
            target: &format!("account:{account_id}"),
            result: &format!("started{}", actor.origin),
            correlation_id: job.id,
        },
    )
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    tokio::spawn(massdelete::run(state.clone(), job.id, account_id, actor.admin_account_id));
    Ok("Deletion started. Progress is shown under Delete Jobs.".into())
}

/// Grants or removes the server admin role. Removing it also revokes the
/// account's admin keys and ends its admin sessions.
pub async fn set_admin(state: &AppState, actor: Actor, account_id: Uuid, admin: bool) -> DataResult<String> {
    let role = if admin { "admin" } else { "user" };
    let mut tx = state.pool.begin().await.map_err(db)?;
    let updated = sqlx::query("UPDATE accounts SET role = $2 WHERE id = $1 AND role <> $2")
        .bind(account_id)
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if updated.rows_affected() == 0 {
        return Err(format!("Account already has the role '{role}'."));
    }
    let mut revoked = 0;
    if !admin {
        let keys: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE admin_keys SET status = 'revoked' WHERE account_id = $1 AND status = 'active' RETURNING id",
        )
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM admin_sessions WHERE admin_key_id = ANY($1)")
            .bind(&keys)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        revoked = keys.len();
    }
    let action = if admin { "account.grant_admin" } else { "account.revoke_admin" };
    audit::append(&mut tx, entry(actor, action, &format!("account:{account_id}"), &actor.ok())).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(if admin {
        "Account is now admin.\n\nTo use the administration in the chat client, the admin opens\nAdmin → Set Up Admin Key… there and gets a public key.\nRegister it here: select the account and press k.".into()
    } else {
        format!("Admin role removed ({revoked} admin key(s) revoked).")
    })
}

/// Deletes an account completely: all its messages for everyone (like the
/// mass deletion), its group memberships (with a notice; groups get a new
/// admin if needed), devices, keys, sessions and invites, then the account.
pub async fn delete_account(state: &AppState, actor: Actor, account_id: Uuid) -> DataResult<String> {
    let username: String = sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(db)?
        .ok_or("Account not found.")?;

    // 1. Messages, for everyone. Runs to completion before the account goes.
    let job = NewJob {
        id: Uuid::new_v4(),
        operation_id: Uuid::new_v4(),
        requested_by: None,
        requested_by_admin: true,
        scope: serde_json::json!({ "type": "account", "account_id": account_id, "username": username }),
    };
    let mut tx = state.pool.begin().await.map_err(db)?;
    conversations::insert_job(&mut tx, &job, ssm_proto::api::DeleteJobStatus::InProgress).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    massdelete::run(state.clone(), job.id, account_id, actor.admin_account_id).await;
    let (status, deleted): (String, i64) =
        sqlx::query_as("SELECT status, affected_messages FROM delete_jobs WHERE id = $1")
            .bind(job.id)
            .fetch_one(&state.pool)
            .await
            .map_err(db)?;
    if status == "failed" || status == "in_progress" {
        return Err(format!("Deleting the messages did not finish ({status}); the account was kept."));
    }

    // 2. Memberships, devices and the account itself.
    let mut tx = state.pool.begin().await.map_err(db)?;
    let memberships: Vec<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id FROM conversation_members WHERE account_id = $1 AND status = 'active'
         ORDER BY conversation_id",
    )
    .bind(account_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db)?;
    let mut woken = Vec::new();
    for conversation_id in memberships {
        let Some(conv) = conversations::lock(&mut tx, conversation_id).await.map_err(db)? else { continue };
        sqlx::query(
            "UPDATE conversation_members SET status = 'removed', role = 'member', left_at = now()
             WHERE conversation_id = $1 AND account_id = $2",
        )
        .bind(conversation_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let notice = ssm_proto::api::SystemNotice::AccountDeleted { username: username.clone() };
        woken.extend(conversations::notice(&mut tx, &conv, notice).await.map_err(db)?);
        if conv.kind != ssm_proto::api::ConversationKind::Group {
            continue;
        }
        if let Some(new_admin) = conversations::ensure_admin(&mut tx, conversation_id).await.map_err(db)? {
            let notice = ssm_proto::api::SystemNotice::AdminChanged { account_id: new_admin };
            woken.extend(conversations::notice(&mut tx, &conv, notice).await.map_err(db)?);
        }
    }
    let devices: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM devices WHERE account_id = $1")
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
    let result =
        format!("ok{}: account '{username}' deleted, {deleted} messages, {} devices", actor.origin, devices.len());
    audit::append(&mut tx, entry(actor, "account.delete", &format!("account:{account_id}"), &result))
        .await
        .map_err(db)?;
    sqlx::query("DELETE FROM accounts WHERE id = $1").bind(account_id).execute(&mut *tx).await.map_err(db)?;
    tx.commit().await.map_err(db)?;
    crate::journal::record(state, &[crate::journal::Entry::Account(account_id)]);
    state.wake(&woken);
    devices.into_iter().for_each(|d| state.close_device(d));
    Ok(format!("Account '{username}' deleted ({deleted} messages deleted for everyone)."))
}

/// After restoring an older backup: deletes again what the deletion journal
/// lists (messages for everyone, accounts completely). Idempotent.
pub async fn replay_deletions(state: &AppState, actor: Actor, journal_path: &std::path::Path) -> DataResult<String> {
    use crate::journal::{self, Entry};
    let entries = journal::read(journal_path).map_err(|e| format!("Cannot read {}: {e}", journal_path.display()))?;
    let message_ids: Vec<Uuid> =
        entries.iter().filter_map(|e| if let Entry::Message(id) = e { Some(*id) } else { None }).collect();
    let mut account_ids: Vec<Uuid> =
        entries.iter().filter_map(|e| if let Entry::Account(id) = e { Some(*id) } else { None }).collect();
    account_ids.sort();
    account_ids.dedup();

    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT conversation_id, id FROM messages
         WHERE id = ANY($1) AND kind = 'encrypted' AND deleted_at IS NULL ORDER BY conversation_id",
    )
    .bind(&message_ids)
    .fetch_all(&state.pool)
    .await
    .map_err(db)?;
    let mut by_conversation: std::collections::BTreeMap<Uuid, Vec<Uuid>> = Default::default();
    for (conversation_id, message_id) in rows {
        by_conversation.entry(conversation_id).or_default().push(message_id);
    }
    let mut messages = 0;
    if !by_conversation.is_empty() {
        let job = NewJob {
            id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            requested_by: None,
            requested_by_admin: true,
            scope: serde_json::json!({ "type": "replay" }),
        };
        let mut tx = state.pool.begin().await.map_err(db)?;
        conversations::insert_job(&mut tx, &job, ssm_proto::api::DeleteJobStatus::InProgress).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        for (conversation_id, ids) in by_conversation {
            let mut tx = state.pool.begin().await.map_err(db)?;
            let Some(conv) = conversations::lock(&mut tx, conversation_id).await.map_err(db)? else { continue };
            let (deleted, woken) =
                conversations::delete_messages(&mut tx, &conv, &ids, None, job.id).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
            state.wake(&woken);
            messages += deleted;
        }
        let mut tx = state.pool.begin().await.map_err(db)?;
        conversations::finish_active_removal(&mut tx, job.id, messages, state.config.backup_retention_days)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
    }

    let mut accounts = 0;
    for account_id in account_ids {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE id = $1)")
            .bind(account_id)
            .fetch_one(&state.pool)
            .await
            .map_err(db)?;
        if exists {
            delete_account(state, actor, account_id).await?;
            accounts += 1;
        }
    }

    let result = format!("{}: {messages} messages and {accounts} accounts deleted again", actor.ok());
    let mut tx = state.pool.begin().await.map_err(db)?;
    audit::append(&mut tx, entry(actor, "deletions.replay", &journal_path.display().to_string(), &result))
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    crate::media::purge_soon(state);
    Ok(format!("Replayed the deletion journal: {messages} messages and {accounts} accounts deleted again."))
}

/// Registers an admin public key (Ed25519, base64url) for an admin account.
/// The key is created in the client under Admin → Set Up Admin Key.
pub async fn add_admin_key(state: &AppState, actor: Actor, account_id: Uuid, public_key: &str) -> DataResult<String> {
    let bytes = B64::decode(public_key.trim()).ok_or("The key is not valid base64url.")?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "An admin key has 32 bytes.".to_owned())?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| "This is not a valid Ed25519 public key.".to_owned())?;
    let mut tx = state.pool.begin().await.map_err(db)?;
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
    match role.as_deref() {
        None => return Err("Account not found.".into()),
        Some("admin") => {}
        Some(_) => return Err("Make the account an admin first (key a).".into()),
    }
    let key_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO admin_keys (id, account_id, public_key) VALUES ($1, $2, $3) ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(key_id)
    .bind(account_id)
    .bind(key.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    if inserted.rows_affected() == 0 {
        return Err("This key is already registered.".into());
    }
    audit::append(&mut tx, entry(actor, "admin_key.add", &format!("account:{account_id}"), &actor.ok()))
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok("Admin key registered. The admin can now open Admin → Administration… in the client.".into())
}
