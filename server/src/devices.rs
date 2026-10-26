//! Per-device event stream and key material housekeeping.

use sqlx::PgConnection;
use ssm_proto::api::EventBody;
use uuid::Uuid;

/// Event retention for undelivered events: longer than the maximum message
/// retention of 365 days (ADR-0004).
pub const EVENT_RETENTION_DAYS: i32 = 400;

fn kind(body: &EventBody) -> &'static str {
    match body {
        EventBody::ToDevice { .. } => "to_device",
        EventBody::Message { .. } => "message",
        EventBody::MessageDeleted { .. } => "message_deleted",
        EventBody::ConversationUpdated { .. } => "conversation_updated",
    }
}

/// Appends an event for `device_id` and returns its sequence number. Callers
/// that push to several devices in one transaction must do so in ascending
/// device id order to keep row-lock order consistent.
pub async fn push_event(conn: &mut PgConnection, device_id: Uuid, body: &EventBody) -> sqlx::Result<i64> {
    let seq: i64 = sqlx::query_scalar("UPDATE devices SET event_seq = event_seq + 1 WHERE id = $1 RETURNING event_seq")
        .bind(device_id)
        .fetch_one(&mut *conn)
        .await?;
    let json = serde_json::to_value(body).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    sqlx::query("INSERT INTO events (device_id, seq, kind, body) VALUES ($1, $2, $3, $4)")
        .bind(device_id)
        .bind(seq)
        .bind(kind(body))
        .bind(json)
        .execute(conn)
        .await?;
    Ok(seq)
}

/// Removes keys and undelivered events of a device that will never be active again.
pub async fn purge_key_material(conn: &mut PgConnection, device_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM one_time_keys WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;
    sqlx::query("DELETE FROM fallback_keys WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;
    sqlx::query("DELETE FROM events WHERE device_id = $1").bind(device_id).execute(conn).await?;
    Ok(())
}

pub async fn purge_expired_events(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM events WHERE created_at < now() - make_interval(days => $1)")
        .bind(EVENT_RETENTION_DAYS)
        .execute(db)
        .await?;
    Ok(())
}

pub enum ActionOutcome {
    Changed(ssm_proto::api::DeviceStatus),
    NotFound,
    /// Not allowed from the current status; nothing changed (but audited).
    InvalidTransition(ssm_proto::api::DeviceStatus),
}

/// Applies an admin device action inside the caller's transaction: status
/// change, ending sessions, purging keys of devices that are gone for good,
/// and the audit entry. The caller commits and then closes the device's
/// connections (`AppState::close_device`) if it is no longer active.
pub async fn apply_action(
    conn: &mut PgConnection,
    device_id: Uuid,
    action: ssm_proto::api::DeviceAction,
    admin_account_id: Option<Uuid>,
    origin: &str,
) -> sqlx::Result<ActionOutcome> {
    use ssm_proto::api::DeviceStatus;

    let current: Option<String> = sqlx::query_scalar("SELECT status FROM devices WHERE id = $1 FOR UPDATE")
        .bind(device_id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(current) = current.as_deref().and_then(DeviceStatus::parse) else { return Ok(ActionOutcome::NotFound) };
    let target = format!("device:{device_id}");
    let audit_action = format!("device.{}", action.as_str());
    let entry = |result| crate::audit::Entry {
        admin_account_id,
        action: &audit_action,
        target: &target,
        result,
        correlation_id: Uuid::new_v4(),
    };

    let Some(next) = action.transition(current) else {
        let result = format!("refused{origin}: invalid transition from {}", current.as_str());
        crate::audit::append(conn, entry(&result)).await?;
        return Ok(ActionOutcome::InvalidTransition(current));
    };
    sqlx::query(
        "UPDATE devices SET status = $2,
             approved_at = CASE WHEN $2 = 'active' AND approved_at IS NULL THEN now() ELSE approved_at END,
             revoked_at  = CASE WHEN $2 = 'revoked' THEN now() ELSE revoked_at END
         WHERE id = $1",
    )
    .bind(device_id)
    .bind(next.as_str())
    .execute(&mut *conn)
    .await?;
    if next != DeviceStatus::Active {
        sqlx::query("DELETE FROM sessions WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;
    }
    if matches!(next, DeviceStatus::Revoked | DeviceStatus::Rejected) {
        purge_key_material(conn, device_id).await?;
    }
    let result = format!("ok{origin}");
    crate::audit::append(conn, entry(&result)).await?;
    Ok(ActionOutcome::Changed(next))
}
