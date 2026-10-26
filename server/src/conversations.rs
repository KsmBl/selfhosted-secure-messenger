//! Conversation domain logic shared by the user and admin APIs.
//!
//! Lock order inside a transaction: conversation row first (`lock`), then
//! device rows in ascending id order (`fan_out`). Keeping this order avoids
//! deadlocks between concurrent senders, deleters and retention changes.

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgConnection, Row};
use ssm_proto::api::{ConversationKind, DeleteJobStatus, EventBody, SystemNotice};
use uuid::Uuid;

use crate::devices;

pub struct Conversation {
    pub id: Uuid,
    pub kind: ConversationKind,
    pub retention_days: i32,
    pub created_by: Uuid,
}

/// Locks the conversation row for the rest of the transaction.
pub async fn lock(conn: &mut PgConnection, id: Uuid) -> sqlx::Result<Option<Conversation>> {
    let row = sqlx::query("SELECT kind, retention_days, created_by FROM conversations WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(conn)
        .await?;
    row.map(|row| {
        Ok(Conversation {
            id,
            kind: ConversationKind::parse(row.try_get("kind")?).ok_or_else(|| sqlx::Error::Decode("kind".into()))?,
            retention_days: row.try_get("retention_days")?,
            created_by: row.try_get("created_by")?,
        })
    })
    .transpose()
}

/// `joined_seq` of an active member, `None` if not an active member.
pub async fn active_membership(
    conn: &mut PgConnection,
    conversation: Uuid,
    account: Uuid,
) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar(
        "SELECT joined_seq FROM conversation_members
         WHERE conversation_id = $1 AND account_id = $2 AND status = 'active'",
    )
    .bind(conversation)
    .bind(account)
    .fetch_optional(conn)
    .await
}

/// Active devices of all active members, ascending.
pub async fn member_devices(conn: &mut PgConnection, conversation: Uuid) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar(
        "SELECT d.id FROM devices d
         JOIN conversation_members m ON m.account_id = d.account_id
         WHERE m.conversation_id = $1 AND m.status = 'active' AND d.status = 'active'
         ORDER BY d.id",
    )
    .bind(conversation)
    .fetch_all(conn)
    .await
}

/// Pushes `body` to every member device except `skip`. Returns `(device, seq)`
/// pairs to wake up through the hub after commit.
pub async fn fan_out(
    conn: &mut PgConnection,
    conversation: Uuid,
    body: &EventBody,
    skip: Option<Uuid>,
) -> sqlx::Result<Vec<(Uuid, i64)>> {
    let mut woken = Vec::new();
    for device in member_devices(conn, conversation).await? {
        if Some(device) != skip {
            woken.push((device, devices::push_event(conn, device, body).await?));
        }
    }
    Ok(woken)
}

pub struct NewMessage<'a> {
    pub sender_account_id: Option<Uuid>,
    pub sender_device_id: Option<Uuid>,
    pub client_id: Option<Uuid>,
    pub encrypted: Option<(&'a str, &'a [u8])>,
    pub notice: Option<&'a SystemNotice>,
}

pub struct StoredMessage {
    pub id: Uuid,
    pub seq: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Appends to the timeline of a locked conversation.
pub async fn append(conn: &mut PgConnection, conv: &Conversation, msg: NewMessage<'_>) -> sqlx::Result<StoredMessage> {
    let seq: i64 = sqlx::query_scalar(
        "UPDATE conversations SET message_seq = message_seq + 1 WHERE id = $1 RETURNING message_seq",
    )
    .bind(conv.id)
    .fetch_one(&mut *conn)
    .await?;
    let id = Uuid::new_v4();
    let created_at = Utc::now();
    let expires_at = created_at + Duration::days(conv.retention_days.into());
    let notice = msg.notice.map(serde_json::to_value).transpose().map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    sqlx::query(
        "INSERT INTO messages (id, conversation_id, seq, kind, sender_account_id, sender_device_id, client_id,
                               session_id, ciphertext, notice, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(conv.id)
    .bind(seq)
    .bind(if msg.encrypted.is_some() { "encrypted" } else { "system" })
    .bind(msg.sender_account_id)
    .bind(msg.sender_device_id)
    .bind(msg.client_id)
    .bind(msg.encrypted.map(|(session, _)| session))
    .bind(msg.encrypted.map(|(_, ciphertext)| ciphertext))
    .bind(notice)
    .bind(created_at)
    .bind(expires_at)
    .execute(conn)
    .await?;
    Ok(StoredMessage { id, seq, created_at, expires_at })
}

/// Appends a system notice and wakes all member devices.
pub async fn notice(
    conn: &mut PgConnection,
    conv: &Conversation,
    notice: SystemNotice,
) -> sqlx::Result<Vec<(Uuid, i64)>> {
    let stored = append(
        conn,
        conv,
        NewMessage {
            sender_account_id: None,
            sender_device_id: None,
            client_id: None,
            encrypted: None,
            notice: Some(&notice),
        },
    )
    .await?;
    let mut woken =
        fan_out(conn, conv.id, &EventBody::Message { conversation_id: conv.id, seq: stored.seq }, None).await?;
    woken.extend(fan_out(conn, conv.id, &EventBody::ConversationUpdated { conversation_id: conv.id }, None).await?);
    Ok(woken)
}

/// Removes the content of messages for everyone (ADR-0004): ciphertext and
/// session id are erased, a tombstone stays, members get `message_deleted`.
/// The job records progress; active data is gone once this returns, so the
/// job moves straight to `backup_purge_pending` until backups have rotated.
pub async fn delete_messages(
    conn: &mut PgConnection,
    conv: &Conversation,
    message_ids: &[Uuid],
    deleted_by: Option<Uuid>,
    job_id: Uuid,
) -> sqlx::Result<(i64, Vec<(Uuid, i64)>)> {
    let deleted: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE messages SET ciphertext = NULL, session_id = NULL, deleted_at = now(), deleted_by = $3, delete_job_id = $4
         WHERE conversation_id = $1 AND id = ANY($2) AND kind = 'encrypted' AND deleted_at IS NULL
         RETURNING id",
    )
    .bind(conv.id)
    .bind(message_ids)
    .bind(deleted_by)
    .bind(job_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut woken = Vec::new();
    for message_id in &deleted {
        woken.extend(
            fan_out(
                conn,
                conv.id,
                &EventBody::MessageDeleted { conversation_id: conv.id, message_id: *message_id },
                None,
            )
            .await?,
        );
    }
    Ok((deleted.len() as i64, woken))
}

pub struct NewJob {
    pub id: Uuid,
    pub operation_id: Uuid,
    pub requested_by: Option<Uuid>,
    pub requested_by_admin: bool,
    pub scope: serde_json::Value,
}

pub async fn insert_job(conn: &mut PgConnection, job: &NewJob, status: DeleteJobStatus) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO delete_jobs (id, operation_id, requested_by, requested_by_admin, scope, status)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(job.id)
    .bind(job.operation_id)
    .bind(job.requested_by)
    .bind(job.requested_by_admin)
    .bind(&job.scope)
    .bind(status.as_str())
    .execute(conn)
    .await?;
    Ok(())
}

/// Active data removed: wait for backups to rotate (never claim more).
pub async fn finish_active_removal(
    conn: &mut PgConnection,
    job_id: Uuid,
    affected: i64,
    backup_retention_days: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE delete_jobs SET status = 'backup_purge_pending', affected_messages = affected_messages + $2,
             backup_purge_due_at = now() + make_interval(days => $3), updated_at = now()
         WHERE id = $1",
    )
    .bind(job_id)
    .bind(affected)
    .bind(backup_retention_days)
    .execute(conn)
    .await?;
    Ok(())
}

/// Background housekeeping: physically remove expired messages and mark
/// delete jobs whose backup window has passed.
pub async fn run_expiry(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM messages WHERE expires_at <= now()").execute(db).await?;
    sqlx::query(
        "UPDATE delete_jobs SET status = 'backup_purge_done', completed_at = now(), updated_at = now()
         WHERE status = 'backup_purge_pending' AND backup_purge_due_at <= now()",
    )
    .execute(db)
    .await?;
    Ok(())
}
