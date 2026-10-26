//! Storage of encrypted media objects (FR-009, FR-011). Files are named by
//! object id in the media directory and contain only `nonce || ciphertext`.
//!
//! Objects are purged (file first, then row) when their message is deleted
//! for everyone, when the message expires (the row loses its message link),
//! or when an upload was never sent within an hour.

use std::path::PathBuf;

use uuid::Uuid;

use crate::AppState;

/// Unsent uploads are removed after this long.
const UNSENT_GRACE: &str = "1 hour";

pub fn path(state: &AppState, media_id: Uuid) -> PathBuf {
    state.config.media_dir.join(media_id.to_string())
}

/// Deletes files and rows of media that must go. Idempotent.
pub async fn purge(state: &AppState) -> sqlx::Result<u64> {
    let doomed: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM media_objects
         WHERE purge OR (message_id IS NULL AND created_at < now() - $1::interval)",
    )
    .bind(UNSENT_GRACE)
    .fetch_all(&state.pool)
    .await?;
    let mut removed = 0;
    for id in doomed {
        match tokio::fs::remove_file(path(state, id)).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                tracing::warn!(media_id = %id, error = %err, "could not remove media file");
                continue;
            }
        }
        sqlx::query("DELETE FROM media_objects WHERE id = $1").bind(id).execute(&state.pool).await?;
        removed += 1;
    }
    Ok(removed)
}

/// Purges right away (after a deletion) without waiting for the minute job.
pub fn purge_soon(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = purge(&state).await {
            tracing::warn!(error = %err, "media purge failed");
        }
    });
}
