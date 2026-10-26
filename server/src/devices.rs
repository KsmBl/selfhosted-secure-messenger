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
