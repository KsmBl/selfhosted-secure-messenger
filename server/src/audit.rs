//! Hash-chained admin audit log (TDD §10.4).
//!
//! `hash = SHA-256(prev_hash || canonical(entry))`; the first entry chains
//! from 32 zero bytes. Appends are serialized with an advisory lock.

use chrono::{DateTime, SubsecRound, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

const GENESIS: [u8; 32] = [0; 32];
const APPEND_LOCK_KEY: i64 = 0x5353_4d5f_4155_4454; // "SSM_AUDT"

pub struct Entry<'a> {
    pub admin_account_id: Option<Uuid>,
    pub action: &'a str,
    pub target: &'a str,
    pub result: &'a str,
    pub correlation_id: Uuid,
}

fn entry_hash(prev: &[u8], admin: Option<Uuid>, action: &str, target: &str, result: &str, correlation: Uuid, at: DateTime<Utc>) -> Vec<u8> {
    let admin = admin.map(|id| id.to_string()).unwrap_or_default();
    let micros = at.timestamp_micros().to_le_bytes();
    let mut hasher = Sha256::new();
    hasher.update(prev);
    for field in [admin.as_bytes(), action.as_bytes(), target.as_bytes(), result.as_bytes(), correlation.as_bytes(), &micros] {
        hasher.update((field.len() as u32).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_vec()
}

/// Appends an entry inside the caller's transaction.
pub async fn append(conn: &mut PgConnection, entry: Entry<'_>) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(APPEND_LOCK_KEY).execute(&mut *conn).await?;
    let prev: Vec<u8> = sqlx::query_scalar("SELECT hash FROM admin_audit_events ORDER BY id DESC LIMIT 1")
        .fetch_optional(&mut *conn)
        .await?
        .unwrap_or_else(|| GENESIS.to_vec());
    // PostgreSQL stores microseconds; truncate so the hash can be recomputed.
    let at = Utc::now().trunc_subsecs(6);
    let hash = entry_hash(&prev, entry.admin_account_id, entry.action, entry.target, entry.result, entry.correlation_id, at);
    sqlx::query(
        "INSERT INTO admin_audit_events
             (admin_account_id, action, target, result, correlation_id, created_at, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(entry.admin_account_id)
    .bind(entry.action)
    .bind(entry.target)
    .bind(entry.result)
    .bind(entry.correlation_id)
    .bind(at)
    .bind(&prev)
    .bind(&hash)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Appends an entry in its own transaction.
pub async fn append_standalone(pool: &PgPool, entry: Entry<'_>) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    append(&mut tx, entry).await?;
    tx.commit().await
}

/// Recomputes the whole chain. Returns the number of entries, or the id of the
/// first entry that does not match.
pub async fn verify_chain(pool: &PgPool) -> sqlx::Result<Result<u64, i64>> {
    let rows = sqlx::query(
        "SELECT id, admin_account_id, action, target, result, correlation_id, created_at, prev_hash, hash
         FROM admin_audit_events ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut prev = GENESIS.to_vec();
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let stored_prev: Vec<u8> = row.try_get("prev_hash")?;
        let stored_hash: Vec<u8> = row.try_get("hash")?;
        let expected = entry_hash(
            &prev,
            row.try_get("admin_account_id")?,
            row.try_get("action")?,
            row.try_get("target")?,
            row.try_get("result")?,
            row.try_get("correlation_id")?,
            row.try_get("created_at")?,
        );
        if stored_prev != prev || stored_hash != expected {
            return Ok(Err(id));
        }
        prev = stored_hash;
    }
    Ok(Ok(rows.len() as u64))
}
