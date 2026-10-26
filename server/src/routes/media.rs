//! Upload and download of encrypted media objects.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::IntoResponse;
use ssm_proto::api::MediaUploaded;
use uuid::Uuid;

use crate::AppState;
use crate::auth::ActiveDevice;
use crate::conversations;
use crate::error::{ApiError, ApiResult};

/// Stores an encrypted object for a conversation the caller is a member of.
/// It is linked to a message when that message is sent (`media_ids`).
pub async fn upload(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(conversation_id): Path<Uuid>,
    body: Bytes,
) -> ApiResult<Json<MediaUploaded>> {
    if body.is_empty() || body.len() > state.config.max_media_bytes {
        return Err(ApiError::bad_request(format!("media must be 1-{} bytes", state.config.max_media_bytes)));
    }
    let mut conn = state.pool.acquire().await?;
    conversations::active_membership(&mut conn, conversation_id, device.account_id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let media_id = Uuid::new_v4();
    tokio::fs::create_dir_all(&state.config.media_dir).await.map_err(|e| {
        tracing::error!(error = %e, "media directory");
        ApiError::internal()
    })?;
    let path = crate::media::path(&state, media_id);
    tokio::fs::write(&path, &body).await.map_err(|e| {
        tracing::error!(error = %e, "writing media");
        ApiError::internal()
    })?;
    sqlx::query("INSERT INTO media_objects (id, conversation_id, uploader_device_id, size) VALUES ($1, $2, $3, $4)")
        .bind(media_id)
        .bind(conversation_id)
        .bind(device.device_id)
        .bind(body.len() as i64)
        .execute(&mut *conn)
        .await?;
    Ok(Json(MediaUploaded { media_id }))
}

/// Encrypted bytes, for members who could see the message. Deleted or
/// expired messages give 410.
pub async fn download(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Path(media_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let row: Option<(Uuid, Option<i64>, bool, bool)> = sqlx::query_as(
        "SELECT o.conversation_id, m.seq,
                o.purge OR COALESCE(m.deleted_at IS NOT NULL OR m.expires_at <= now(), false),
                o.uploader_device_id = $2
         FROM media_objects o LEFT JOIN messages m ON m.id = o.message_id
         WHERE o.id = $1",
    )
    .bind(media_id)
    .bind(device.device_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some((conversation_id, seq, gone, own_upload)) = row else { return Err(ApiError::not_found()) };
    let mut conn = state.pool.acquire().await?;
    let joined_seq = conversations::active_membership(&mut conn, conversation_id, device.account_id)
        .await?
        .ok_or_else(ApiError::not_found)?;
    match seq {
        // Not sent yet: only the uploading device may read it back.
        None if !own_upload => return Err(ApiError::not_found()),
        Some(seq) if seq <= joined_seq => return Err(ApiError::not_found()),
        _ => {}
    }
    if gone {
        return Err(ApiError::new(axum::http::StatusCode::GONE, "media-deleted"));
    }
    let bytes = tokio::fs::read(crate::media::path(&state, media_id))
        .await
        .map_err(|_| ApiError::new(axum::http::StatusCode::GONE, "media-deleted"))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes))
}
