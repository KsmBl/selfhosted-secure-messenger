//! Admin API (FR-016 – FR-020, ADR-0006). Every handler authorizes through
//! `AdminAuth`; state-changing actions are written to the audit log.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use ssm_proto::api::{
    AccountInfo, AccountRoleRequest, AccountStatusRequest, AddAdminKeyRequest, AdminDeviceInfo, AdminJob,
    AdminKeyLookup, AdminOutcome, AdminOverview, AdminSessionRequest, AuditEvent, ChallengeResponse, ConfirmRequest,
    ContentSummary, CreateAccountRequest, DeleteJobInfo, DeleteJobStatus, DeviceAction, DeviceStatus, InviteResponse,
    MassDeleteRequest, SessionResponse,
};
use ssm_proto::{B64, signing};
use uuid::Uuid;

use super::conversations::job_info;
use super::device::challenge_response;
use crate::audit::{self, Entry};
use crate::auth::{self, AdminAuth, Purpose};
use crate::conversations::{self, NewJob};
use crate::devices::{self, ActionOutcome};
use crate::error::{ApiError, ApiResult};
use crate::manage::{self, Actor};
use crate::{AppState, secrets};
use crate::{accounts, massdelete};

fn rfc3339(row: &sqlx::postgres::PgRow, column: &str) -> ApiResult<String> {
    Ok(row.try_get::<DateTime<Utc>, _>(column)?.to_rfc3339())
}

pub async fn auth_challenge(State(state): State<AppState>) -> ApiResult<Json<ChallengeResponse>> {
    let nonce = auth::issue_challenge(&state.pool, Purpose::Admin).await?;
    Ok(Json(challenge_response(nonce)))
}

pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<AdminSessionRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let mut tx = state.pool.begin().await?;
    auth::consume_challenge(&mut *tx, &req.nonce.0, Purpose::Admin).await?;
    let public_key: Vec<u8> = sqlx::query_scalar(
        "SELECT k.public_key FROM admin_keys k JOIN accounts a ON a.id = k.account_id
         WHERE k.id = $1 AND k.status = 'active' AND a.role = 'admin' AND a.status = 'active'",
    )
    .bind(req.admin_key_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::forbidden("invalid-signature"))?;
    if !signing::verify(&public_key, &signing::admin_auth_message(&req.nonce.0, req.admin_key_id), &req.signature.0) {
        return Err(ApiError::forbidden("invalid-signature"));
    }
    let (token, hash) = secrets::new_token();
    sqlx::query("INSERT INTO admin_sessions (token_hash, admin_key_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash)
        .bind(req.admin_key_id)
        .bind(Utc::now() + auth::ADMIN_SESSION_TTL)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(SessionResponse { token, expires_in_secs: auth::ADMIN_SESSION_TTL.num_seconds() as u64 }))
}

/// Nonce for confirming a destructive action; requires an admin session.
pub async fn confirm_challenge(State(state): State<AppState>, _admin: AdminAuth) -> ApiResult<Json<ChallengeResponse>> {
    let nonce = auth::issue_challenge(&state.pool, Purpose::AdminConfirm).await?;
    Ok(Json(challenge_response(nonce)))
}

/// Checks the fresh confirmation signature of the logged-in admin key.
async fn verify_confirmation(
    conn: &mut sqlx::PgConnection,
    admin: AdminAuth,
    confirm: Option<&ConfirmRequest>,
    action: &str,
    target: &str,
) -> ApiResult<()> {
    let confirm = confirm.ok_or_else(|| ApiError::forbidden("confirmation-required"))?;
    auth::consume_challenge(&mut *conn, &confirm.nonce.0, Purpose::AdminConfirm).await?;
    let public_key: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM admin_keys WHERE id = $1")
        .bind(admin.admin_key_id)
        .fetch_one(&mut *conn)
        .await?;
    let message = signing::admin_confirm_message(&confirm.nonce.0, action, target);
    if !signing::verify(&public_key, &message, &confirm.signature.0) {
        return Err(ApiError::forbidden("invalid-confirmation"));
    }
    Ok(())
}

pub async fn create_account(
    State(state): State<AppState>,
    admin: AdminAuth,
    Json(req): Json<CreateAccountRequest>,
) -> ApiResult<Json<InviteResponse>> {
    if !accounts::is_valid_username(&req.username) {
        return Err(ApiError::bad_request("username must be 3-32 characters of [a-z0-9_.-]"));
    }
    let mut tx = state.pool.begin().await?;
    let account_id = accounts::create_account(&mut tx, &req.username, "user")
        .await?
        .ok_or_else(|| ApiError::conflict("username-taken"))?;
    let (invite_code, expires_at) = accounts::create_invite(&mut tx, account_id).await?;
    audit::append(
        &mut tx,
        Entry {
            admin_account_id: Some(admin.account_id),
            action: "account.create",
            target: &format!("account:{account_id}"),
            result: "ok",
            correlation_id: Uuid::new_v4(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(InviteResponse { account_id, invite_code, expires_at: expires_at.to_rfc3339() }))
}

pub async fn create_invite(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
) -> ApiResult<Json<InviteResponse>> {
    let mut tx = state.pool.begin().await?;
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1 AND status = 'active'")
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?;
    exists.ok_or_else(ApiError::not_found)?;
    let (invite_code, expires_at) = accounts::create_invite(&mut tx, account_id).await?;
    audit::append(
        &mut tx,
        Entry {
            admin_account_id: Some(admin.account_id),
            action: "invite.create",
            target: &format!("account:{account_id}"),
            result: "ok",
            correlation_id: Uuid::new_v4(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(InviteResponse { account_id, invite_code, expires_at: expires_at.to_rfc3339() }))
}

pub async fn list_accounts(State(state): State<AppState>, _admin: AdminAuth) -> ApiResult<Json<Vec<AccountInfo>>> {
    let rows = sqlx::query(
        "SELECT a.id, a.username, a.role, a.status, a.created_at,
                (SELECT count(*) FROM devices d WHERE d.account_id = a.id AND d.status = 'active') AS devices,
                (SELECT count(*) FROM messages m WHERE m.sender_account_id = a.id AND m.kind = 'encrypted'
                    AND m.deleted_at IS NULL AND m.expires_at > now()) AS messages
         FROM accounts a ORDER BY a.username",
    )
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(AccountInfo {
                account_id: row.try_get("id")?,
                username: row.try_get("username")?,
                role: row.try_get("role")?,
                status: row.try_get("status")?,
                created_at: rfc3339(row, "created_at")?,
                active_devices: row.try_get("devices")?,
                messages: row.try_get("messages")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

#[derive(Debug, Deserialize)]
pub struct DeviceFilter {
    status: Option<String>,
}

pub async fn list_devices(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(filter): Query<DeviceFilter>,
) -> ApiResult<Json<Vec<AdminDeviceInfo>>> {
    let status = match filter.status.as_deref() {
        Some(s) => Some(DeviceStatus::parse(s).ok_or_else(|| ApiError::bad_request("unknown status"))?.as_str()),
        None => None,
    };
    let rows = sqlx::query(
        "SELECT d.id, d.account_id, a.username, d.display_name, d.status, d.olm_fingerprint_key, d.created_at
         FROM devices d JOIN accounts a ON a.id = d.account_id
         WHERE $1::text IS NULL OR d.status = $1
         ORDER BY d.created_at",
    )
    .bind(status)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(AdminDeviceInfo {
                device_id: row.try_get("id")?,
                account_id: row.try_get("account_id")?,
                username: row.try_get("username")?,
                display_name: row.try_get("display_name")?,
                status: DeviceStatus::parse(row.try_get("status")?).ok_or_else(ApiError::internal)?,
                olm_fingerprint_key: B64(row.try_get("olm_fingerprint_key")?),
                created_at: rfc3339(row, "created_at")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

/// approve | reject | disable | enable | revoke. Revoke needs a confirmation
/// signature. Leaving `active` ends all sessions of the device immediately;
/// revoked and rejected devices are deleted completely.
pub async fn device_action(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path((device_id, action)): Path<(Uuid, String)>,
    body: Bytes,
) -> ApiResult<Json<AdminDeviceInfo>> {
    let action = DeviceAction::parse(&action).ok_or_else(ApiError::not_found)?;
    let confirm: Option<ConfirmRequest> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("invalid confirmation body"))?)
    };
    let target = format!("device:{device_id}");
    let mut tx = state.pool.begin().await?;
    if action.is_destructive() {
        verify_confirmation(&mut tx, admin, confirm.as_ref(), action.as_str(), &target).await?;
    }
    // Read before the action: revoked and rejected devices are deleted.
    let row = sqlx::query(
        "SELECT d.id, d.account_id, a.username, d.display_name, d.status, d.olm_fingerprint_key, d.created_at
         FROM devices d JOIN accounts a ON a.id = d.account_id WHERE d.id = $1",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    let next = match devices::apply_action(&mut tx, device_id, action, Some(admin.account_id), "").await? {
        ActionOutcome::Changed(next) => next,
        ActionOutcome::NotFound => return Err(ApiError::not_found()),
        ActionOutcome::InvalidTransition(current) => {
            tx.commit().await?;
            return Err(ApiError::conflict("invalid-transition").with_detail(format!(
                "cannot {} a {} device",
                action.as_str(),
                current.as_str()
            )));
        }
    };

    tx.commit().await?;
    if next != DeviceStatus::Active {
        state.close_device(device_id);
    }
    tracing::info!(%device_id, action = action.as_str(), "admin device action");

    Ok(Json(AdminDeviceInfo {
        device_id,
        account_id: row.try_get("account_id")?,
        username: row.try_get("username")?,
        display_name: row.try_get("display_name")?,
        status: next,
        olm_fingerprint_key: B64(row.try_get("olm_fingerprint_key")?),
        created_at: rfc3339(&row, "created_at")?,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    before: Option<i64>,
    limit: Option<i64>,
}

/// Newest first; page with `before=<id>`.
pub async fn audit_events(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEvent>>> {
    let limit = query.limit.unwrap_or(100).clamp(1, 100);
    let rows = sqlx::query(
        "SELECT e.id, e.admin_account_id, e.action, e.target, e.result, e.correlation_id, e.created_at, e.hash,
                COALESCE('account ' || a.username,
                         'device ' || d.display_name || ' (' || da.username || ')',
                         e.target) AS target_label
         FROM admin_audit_events e
         LEFT JOIN accounts a ON e.target = 'account:' || a.id::text
         LEFT JOIN devices d ON e.target = 'device:' || d.id::text
         LEFT JOIN accounts da ON da.id = d.account_id
         WHERE $1::bigint IS NULL OR e.id < $1
         ORDER BY e.id DESC LIMIT $2",
    )
    .bind(query.before)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(AuditEvent {
                id: row.try_get("id")?,
                admin_account_id: row.try_get("admin_account_id")?,
                action: row.try_get("action")?,
                target: row.try_get("target")?,
                result: row.try_get("result")?,
                correlation_id: row.try_get("correlation_id")?,
                created_at: rfc3339(row, "created_at")?,
                hash: hex::encode(row.try_get::<Vec<u8>, _>("hash")?),
                target_label: row.try_get("target_label")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

pub const MASS_DELETE_ACTION: &str = "delete-all-content";

/// Scope shown to the admin before confirming a mass deletion.
pub async fn content_summary(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(account_id): Path<Uuid>,
) -> ApiResult<Json<ContentSummary>> {
    let username: String = sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let (messages, conversations): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(DISTINCT conversation_id) FROM messages
         WHERE sender_account_id = $1 AND kind = 'encrypted' AND deleted_at IS NULL AND expires_at > now()",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(ContentSummary { account_id, username, messages, conversations }))
}

/// Deletes everything an account has sent, for everyone (FR-018). Requires a
/// confirmation signature; runs asynchronously; idempotent per operation id.
pub async fn delete_all_content(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
    Json(req): Json<MassDeleteRequest>,
) -> ApiResult<Json<DeleteJobInfo>> {
    let target = format!("account:{account_id}");
    let mut tx = state.pool.begin().await?;
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM delete_jobs WHERE requested_by = $1 AND operation_id = $2")
            .bind(admin.account_id)
            .bind(req.operation_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(job_id) = existing {
        return Ok(Json(job_info(&mut tx, job_id).await?));
    }
    let confirm = ConfirmRequest { nonce: req.nonce, signature: req.signature };
    verify_confirmation(&mut tx, admin, Some(&confirm), MASS_DELETE_ACTION, &target).await?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1").bind(account_id).fetch_optional(&mut *tx).await?;
    exists.ok_or_else(ApiError::not_found)?;

    let job = NewJob {
        id: Uuid::new_v4(),
        operation_id: req.operation_id,
        requested_by: Some(admin.account_id),
        requested_by_admin: true,
        scope: serde_json::json!({ "type": "account", "account_id": account_id }),
    };
    conversations::insert_job(&mut tx, &job, DeleteJobStatus::InProgress).await?;
    audit::append(
        &mut tx,
        Entry {
            admin_account_id: Some(admin.account_id),
            action: "account.delete_all_content",
            target: &target,
            result: "started",
            correlation_id: job.id,
        },
    )
    .await?;
    let info = job_info(&mut tx, job.id).await?;
    tx.commit().await?;
    tokio::spawn(massdelete::run(state.clone(), job.id, account_id, Some(admin.account_id)));
    Ok(Json(info))
}

pub async fn delete_job(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(job_id): Path<Uuid>,
) -> ApiResult<Json<DeleteJobInfo>> {
    let mut conn = state.pool.acquire().await?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM delete_jobs WHERE id = $1").bind(job_id).fetch_optional(&mut *conn).await?;
    exists.ok_or_else(ApiError::not_found)?;
    Ok(Json(job_info(&mut conn, job_id).await?))
}

// ---- Admin client support ----

#[derive(Debug, Deserialize)]
pub struct KeyLookupQuery {
    public_key: String,
}

/// Unauthenticated (rate-limited): the key id for an admin public key, so a
/// client that created its key can log in without being told the id.
pub async fn lookup_admin_key(
    State(state): State<AppState>,
    Query(query): Query<KeyLookupQuery>,
) -> ApiResult<Json<AdminKeyLookup>> {
    let key = B64::decode(&query.public_key).ok_or_else(|| ApiError::bad_request("invalid public key"))?;
    let admin_key_id: Uuid =
        sqlx::query_scalar("SELECT id FROM admin_keys WHERE public_key = $1 AND status = 'active'")
            .bind(key)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(ApiError::not_found)?;
    Ok(Json(AdminKeyLookup { admin_key_id }))
}

pub async fn overview(State(state): State<AppState>, _admin: AdminAuth) -> ApiResult<Json<AdminOverview>> {
    let stats = manage::stats(&state).await.map_err(|e| ApiError::internal().with_detail(e))?;
    let audit_broken_at = audit::verify_chain(&state.pool).await?.err();
    Ok(Json(AdminOverview {
        accounts: stats.accounts,
        admins: stats.admins,
        devices_pending: stats.devices_pending,
        devices_active: stats.devices_active,
        devices_disabled: stats.devices_disabled,
        conversations: stats.conversations,
        messages: stats.messages,
        jobs_running: stats.jobs_running,
        jobs_backup_pending: stats.jobs_backup_pending,
        audit_entries: stats.audit_entries,
        audit_broken_at,
    }))
}

pub async fn list_jobs(State(state): State<AppState>, _admin: AdminAuth) -> ApiResult<Json<Vec<AdminJob>>> {
    let rows = sqlx::query(
        "SELECT j.id, j.scope, j.status, j.affected_messages, j.created_at, j.backup_purge_due_at, j.error_summary,
                COALESCE(a.username, j.scope->>'username' || ' (deleted)') AS username
         FROM delete_jobs j LEFT JOIN accounts a ON a.id = (j.scope->>'account_id')::uuid
         ORDER BY j.created_at DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            let scope: serde_json::Value = row.try_get("scope")?;
            let username: Option<String> = row.try_get("username")?;
            let scope = match scope["type"].as_str() {
                Some("account") => format!("all content of {}", username.as_deref().unwrap_or("?")),
                Some("message") => "one message".to_owned(),
                Some("messages") if scope["all"].as_bool() == Some(true) => "all messages of a conversation".to_owned(),
                Some("messages") => format!("{} messages", scope["count"].as_u64().unwrap_or(0)),
                Some("replay") => "deletions replayed after a restore".to_owned(),
                other => other.unwrap_or("?").to_owned(),
            };
            Ok(AdminJob {
                job_id: row.try_get("id")?,
                scope,
                status: DeleteJobStatus::parse(row.try_get("status")?).ok_or_else(ApiError::internal)?,
                affected_messages: row.try_get("affected_messages")?,
                created_at: rfc3339(row, "created_at")?,
                backup_purge_due_at: row
                    .try_get::<Option<DateTime<Utc>>, _>("backup_purge_due_at")?
                    .map(|t| t.to_rfc3339()),
                error_summary: row.try_get("error_summary")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

/// Runs a confirmed management operation for `account_id`.
async fn confirmed(
    state: &AppState,
    admin: AdminAuth,
    confirm: &ConfirmRequest,
    action: &str,
    account_id: Uuid,
) -> ApiResult<()> {
    let mut tx = state.pool.begin().await?;
    verify_confirmation(&mut tx, admin, Some(confirm), action, &format!("account:{account_id}")).await?;
    tx.commit().await?;
    Ok(())
}

fn outcome(result: manage::DataResult<String>) -> ApiResult<Json<AdminOutcome>> {
    result
        .map(|message| Json(AdminOutcome { message }))
        .map_err(|e| ApiError::conflict("operation-refused").with_detail(e))
}

pub async fn set_account_status(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
    Json(req): Json<AccountStatusRequest>,
) -> ApiResult<Json<AdminOutcome>> {
    let action = if req.disabled { "disable-account" } else { "enable-account" };
    confirmed(&state, admin, &req.confirm, action, account_id).await?;
    if req.disabled && account_id == admin.account_id {
        return Err(ApiError::conflict("not-on-self").with_detail("you cannot lock your own account"));
    }
    outcome(manage::set_account_status(&state, Actor::admin(admin.account_id), account_id, req.disabled).await)
}

pub async fn set_account_role(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
    Json(req): Json<AccountRoleRequest>,
) -> ApiResult<Json<AdminOutcome>> {
    let action = if req.admin { "grant-admin" } else { "revoke-admin" };
    confirmed(&state, admin, &req.confirm, action, account_id).await?;
    if !req.admin && account_id == admin.account_id {
        return Err(ApiError::conflict("not-on-self").with_detail("you cannot remove your own admin role"));
    }
    outcome(manage::set_admin(&state, Actor::admin(admin.account_id), account_id, req.admin).await)
}

pub async fn add_admin_key(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
    Json(req): Json<AddAdminKeyRequest>,
) -> ApiResult<Json<AdminOutcome>> {
    confirmed(&state, admin, &req.confirm, "add-admin-key", account_id).await?;
    let key = B64::encode(&req.public_key.0);
    outcome(manage::add_admin_key(&state, Actor::admin(admin.account_id), account_id, &key).await)
}

/// Deletes an account completely (messages for everyone, devices, keys).
pub async fn delete_account(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
    Json(confirm): Json<ConfirmRequest>,
) -> ApiResult<Json<AdminOutcome>> {
    confirmed(&state, admin, &confirm, "delete-account", account_id).await?;
    if account_id == admin.account_id {
        return Err(ApiError::conflict("not-on-self").with_detail("you cannot delete your own account"));
    }
    outcome(manage::delete_account(&state, Actor::admin(admin.account_id), account_id).await)
}
