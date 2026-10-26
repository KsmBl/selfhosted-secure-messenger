//! Olm key distribution: one-time keys, device lookup and to-device messages.

use axum::Json;
use axum::extract::{Path, State};
use sqlx::Row;
use ssm_proto::B64;
use ssm_proto::api::{
    AccountLookup, ClaimKeysRequest, ClaimKeysResponse, ClaimedKey, EventBody, OneTimeKey, PeerDevice,
    SendToDeviceRequest, SendToDeviceResponse, UploadKeysRequest, UploadKeysResponse,
};
use uuid::Uuid;

use crate::AppState;
use crate::auth::ActiveDevice;
use crate::devices;
use crate::error::{ApiError, ApiResult};

pub const MAX_ONE_TIME_KEYS: i64 = 100;
const MAX_CLAIM: usize = 100;
const MAX_TO_DEVICE: usize = 1000;
const MAX_TO_DEVICE_CIPHERTEXT: usize = 64 * 1024;

fn validate_key(key: &OneTimeKey) -> ApiResult<[u8; 32]> {
    if key.key_id.is_empty() || key.key_id.chars().count() > 64 {
        return Err(ApiError::bad_request("key_id must be 1-64 characters"));
    }
    key.public_key.to_array().ok_or_else(|| ApiError::bad_request("public_key must be 32 bytes"))
}

async fn one_time_key_count(conn: &mut sqlx::PgConnection, device_id: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT count(*) FROM one_time_keys WHERE device_id = $1").bind(device_id).fetch_one(conn).await
}

/// Stores new one-time keys (at most 100 per device) and optionally replaces
/// the fallback key. An empty request just returns the current count.
pub async fn upload(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Json(req): Json<UploadKeysRequest>,
) -> ApiResult<Json<UploadKeysResponse>> {
    if req.one_time_keys.len() as i64 > MAX_ONE_TIME_KEYS {
        return Err(ApiError::bad_request("too many one-time keys"));
    }
    let mut tx = state.pool.begin().await?;
    for key in &req.one_time_keys {
        let public_key = validate_key(key)?;
        sqlx::query(
            "INSERT INTO one_time_keys (device_id, key_id, public_key) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(device.device_id)
        .bind(&key.key_id)
        .bind(public_key.as_slice())
        .execute(&mut *tx)
        .await?;
    }
    if let Some(key) = &req.fallback_key {
        let public_key = validate_key(key)?;
        sqlx::query(
            "INSERT INTO fallback_keys (device_id, key_id, public_key) VALUES ($1, $2, $3)
             ON CONFLICT (device_id) DO UPDATE SET key_id = EXCLUDED.key_id, public_key = EXCLUDED.public_key",
        )
        .bind(device.device_id)
        .bind(&key.key_id)
        .bind(public_key.as_slice())
        .execute(&mut *tx)
        .await?;
    }
    let count = one_time_key_count(&mut tx, device.device_id).await?;
    if count > MAX_ONE_TIME_KEYS {
        return Err(ApiError::bad_request(format!("at most {MAX_ONE_TIME_KEYS} one-time keys may be stored")));
    }
    tx.commit().await?;
    Ok(Json(UploadKeysResponse { one_time_key_count: count as u32 }))
}

/// Hands out one key per requested active device: a one-time key (consumed)
/// or, if none is left, the device's fallback key.
pub async fn claim(
    State(state): State<AppState>,
    _caller: ActiveDevice,
    Json(req): Json<ClaimKeysRequest>,
) -> ApiResult<Json<ClaimKeysResponse>> {
    let mut device_ids = req.device_ids;
    device_ids.sort();
    device_ids.dedup();
    if device_ids.len() > MAX_CLAIM {
        return Err(ApiError::bad_request(format!("at most {MAX_CLAIM} devices per request")));
    }

    let mut tx = state.pool.begin().await?;
    let mut keys = Vec::new();
    let mut unavailable = Vec::new();
    for device_id in device_ids {
        let active: Option<Uuid> = sqlx::query_scalar("SELECT id FROM devices WHERE id = $1 AND status = 'active'")
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?;
        if active.is_none() {
            unavailable.push(device_id);
            continue;
        }
        let one_time = sqlx::query(
            "DELETE FROM one_time_keys WHERE (device_id, key_id) = (
                 SELECT device_id, key_id FROM one_time_keys WHERE device_id = $1
                 ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED)
             RETURNING key_id, public_key",
        )
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (row, fallback) = match one_time {
            Some(row) => (Some(row), false),
            None => (
                sqlx::query("SELECT key_id, public_key FROM fallback_keys WHERE device_id = $1")
                    .bind(device_id)
                    .fetch_optional(&mut *tx)
                    .await?,
                true,
            ),
        };
        match row {
            Some(row) => keys.push(ClaimedKey {
                device_id,
                key_id: row.try_get("key_id")?,
                public_key: B64(row.try_get("public_key")?),
                fallback,
            }),
            None => unavailable.push(device_id),
        }
    }
    tx.commit().await?;
    Ok(Json(ClaimKeysResponse { keys, unavailable }))
}

pub async fn lookup_account(
    State(state): State<AppState>,
    _caller: ActiveDevice,
    Path(username): Path<String>,
) -> ApiResult<Json<AccountLookup>> {
    let account_id: Uuid = sqlx::query_scalar("SELECT id FROM accounts WHERE username = $1 AND status = 'active'")
        .bind(&username)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(AccountLookup { account_id, username }))
}

/// Active devices of an account with their Olm identity keys.
pub async fn account_devices(
    State(state): State<AppState>,
    _caller: ActiveDevice,
    Path(account_id): Path<Uuid>,
) -> ApiResult<Json<Vec<PeerDevice>>> {
    let rows = sqlx::query(
        "SELECT d.id, d.display_name, d.olm_identity_key, d.olm_fingerprint_key
         FROM devices d JOIN accounts a ON a.id = d.account_id
         WHERE d.account_id = $1 AND d.status = 'active' AND a.status = 'active'
         ORDER BY d.created_at",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(PeerDevice {
                device_id: row.try_get("id")?,
                display_name: row.try_get("display_name")?,
                olm_identity_key: B64(row.try_get("olm_identity_key")?),
                olm_fingerprint_key: B64(row.try_get("olm_fingerprint_key")?),
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

/// Queues Olm-encrypted messages (e.g. Megolm session keys) for other devices.
/// The sender's identity key is attached by the server, not the client.
pub async fn send_to_device(
    State(state): State<AppState>,
    ActiveDevice(sender): ActiveDevice,
    Json(req): Json<SendToDeviceRequest>,
) -> ApiResult<Json<SendToDeviceResponse>> {
    let mut messages = req.messages;
    if messages.len() > MAX_TO_DEVICE {
        return Err(ApiError::bad_request(format!("at most {MAX_TO_DEVICE} messages per request")));
    }
    if messages.iter().any(|m| m.message_type > 1 || m.ciphertext.0.is_empty()) {
        return Err(ApiError::bad_request("invalid message_type or empty ciphertext"));
    }
    if messages.iter().any(|m| m.ciphertext.0.len() > MAX_TO_DEVICE_CIPHERTEXT) {
        return Err(ApiError::bad_request("ciphertext too large"));
    }
    // Consistent lock order across concurrent senders (see devices::push_event).
    messages.sort_by_key(|m| m.device_id);

    let mut tx = state.pool.begin().await?;
    let sender_identity_key: Vec<u8> = sqlx::query_scalar("SELECT olm_identity_key FROM devices WHERE id = $1")
        .bind(sender.device_id)
        .fetch_one(&mut *tx)
        .await?;
    let mut delivered = Vec::new();
    let mut skipped = Vec::new();
    for message in messages {
        let active: Option<Uuid> = sqlx::query_scalar("SELECT id FROM devices WHERE id = $1 AND status = 'active'")
            .bind(message.device_id)
            .fetch_optional(&mut *tx)
            .await?;
        if active.is_none() {
            skipped.push(message.device_id);
            continue;
        }
        let body = EventBody::ToDevice {
            sender_device_id: sender.device_id,
            sender_identity_key: B64(sender_identity_key.clone()),
            message_type: message.message_type,
            ciphertext: message.ciphertext,
        };
        let seq = devices::push_event(&mut tx, message.device_id, &body).await?;
        delivered.push((message.device_id, seq));
    }
    tx.commit().await?;
    state.wake(&delivered);
    Ok(Json(SendToDeviceResponse { delivered: delivered.len() as u32, skipped }))
}
