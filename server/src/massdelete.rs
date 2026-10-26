//! Admin mass deletion (FR-018): all messages sent by one account, across all
//! conversations, deleted for everyone. Runs as a background job, one
//! conversation per transaction, so progress and partial results are visible
//! and a failure leaves completed conversations deleted.

use uuid::Uuid;

use crate::AppState;
use crate::audit::{self, Entry};
use crate::conversations;

pub const AUDIT_ACTION_FINISHED: &str = "account.delete_all_content.finished";

/// Deletes the account's messages conversation by conversation. Returns the
/// number of messages deleted.
async fn process(state: &AppState, job_id: Uuid, account_id: Uuid) -> sqlx::Result<i64> {
    let conversation_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT conversation_id FROM messages
         WHERE sender_account_id = $1 AND kind = 'encrypted' AND deleted_at IS NULL",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;

    let mut total = 0;
    for conversation_id in conversation_ids {
        let mut tx = state.pool.begin().await?;
        let Some(conv) = conversations::lock(&mut tx, conversation_id).await? else { continue };
        let message_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM messages
             WHERE conversation_id = $1 AND sender_account_id = $2 AND kind = 'encrypted' AND deleted_at IS NULL",
        )
        .bind(conversation_id)
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await?;
        let (deleted, woken) = conversations::delete_messages(&mut tx, &conv, &message_ids, None, job_id).await?;
        sqlx::query(
            "UPDATE delete_jobs SET affected_messages = affected_messages + $2, updated_at = now() WHERE id = $1",
        )
        .bind(job_id)
        .bind(deleted)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        state.wake(&woken);
        total += deleted;
    }
    Ok(total)
}

/// Runs a mass deletion job to completion and records the outcome.
pub async fn run(state: AppState, job_id: Uuid, account_id: Uuid, admin_account_id: Option<Uuid>) {
    let outcome = process(&state, job_id, account_id).await;
    let result = match &outcome {
        Ok(total) => format!("ok: {total} messages deleted"),
        Err(err) => format!("failed: {err}"),
    };
    let recorded = async {
        let mut tx = state.pool.begin().await?;
        match &outcome {
            Ok(_) => {
                conversations::finish_active_removal(&mut tx, job_id, 0, state.config.backup_retention_days).await?
            }
            Err(err) => {
                sqlx::query(
                    "UPDATE delete_jobs SET status = 'failed', error_summary = $2, updated_at = now() WHERE id = $1",
                )
                .bind(job_id)
                .bind(err.to_string())
                .execute(&mut *tx)
                .await?;
            }
        }
        audit::append(
            &mut tx,
            Entry {
                admin_account_id,
                action: AUDIT_ACTION_FINISHED,
                target: &format!("account:{account_id}"),
                result: &result,
                correlation_id: job_id,
            },
        )
        .await?;
        tx.commit().await
    };
    if let Err(err) = recorded.await {
        tracing::error!(%job_id, error = %err, "recording mass deletion outcome failed");
    }
    tracing::info!(%job_id, %account_id, result, "mass deletion finished");
}

/// Restarts jobs that were interrupted (e.g. by a server restart). Deleting
/// is idempotent, so re-running from the start is safe.
pub async fn resume_interrupted(state: &AppState) -> sqlx::Result<usize> {
    let rows: Vec<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, (scope->>'account_id')::uuid, requested_by FROM delete_jobs
         WHERE status = 'in_progress' AND requested_by_admin AND scope->>'type' = 'account'",
    )
    .fetch_all(&state.pool)
    .await?;
    let count = rows.len();
    for (job_id, account_id, admin) in rows {
        tokio::spawn(run(state.clone(), job_id, account_id, admin));
    }
    Ok(count)
}
