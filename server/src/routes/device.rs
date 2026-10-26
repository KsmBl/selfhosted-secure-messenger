//! User API: challenges, enrollment, device sessions and device status.

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use sqlx::Row;
use ssm_proto::api::{
    ChallengeResponse, DeviceInfo, DeviceStatus, DeviceStatusResponse, EnrollRequest, EnrollResponse, SessionRequest,
    SessionResponse,
};
use ssm_proto::{B64, signing};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{self, ActiveDevice, AuthDevice, Purpose};
use crate::error::{ApiError, ApiResult};
use crate::secrets;

pub async fn enroll_challenge(State(state): State<AppState>) -> ApiResult<Json<ChallengeResponse>> {
    let nonce = auth::issue_challenge(&state.pool, Purpose::Enroll).await?;
    Ok(Json(challenge_response(nonce)))
}

pub async fn session_challenge(State(state): State<AppState>) -> ApiResult<Json<ChallengeResponse>> {
    let nonce = auth::issue_challenge(&state.pool, Purpose::Device).await?;
    Ok(Json(challenge_response(nonce)))
}

pub(crate) fn challenge_response(nonce: Vec<u8>) -> ChallengeResponse {
    ChallengeResponse { nonce: B64(nonce), expires_in_secs: auth::CHALLENGE_TTL.num_seconds() as u64 }
}

fn key32(value: &B64, field: &str) -> ApiResult<[u8; 32]> {
    value.to_array().ok_or_else(|| ApiError::bad_request(format!("{field} must be 32 bytes")))
}

/// Registers a new device as `pending` (TDD §5.2). Invalid invites and unknown
/// usernames fail identically to avoid account enumeration.
pub async fn enroll(State(state): State<AppState>, Json(req): Json<EnrollRequest>) -> ApiResult<Json<EnrollResponse>> {
    let display_name = req.display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > 64 {
        return Err(ApiError::bad_request("display_name must be 1-64 characters"));
    }
    let signing_key = key32(&req.signing_key, "signing_key")?;
    let olm_identity_key = key32(&req.olm_identity_key, "olm_identity_key")?;
    let olm_fingerprint_key = key32(&req.olm_fingerprint_key, "olm_fingerprint_key")?;

    let mut tx = state.pool.begin().await?;
    auth::consume_challenge(&mut *tx, &req.nonce.0, Purpose::Enroll).await?;

    let message = signing::enroll_message(&req.nonce.0, &signing_key, &olm_identity_key, &olm_fingerprint_key);
    if !signing::verify(&signing_key, &message, &req.signature.0) {
        return Err(ApiError::forbidden("invalid-signature"));
    }

    let refused = || ApiError::forbidden("enrollment-refused");
    let account_id: Uuid = match (&req.invite_code, &req.username) {
        (Some(code), None) => sqlx::query_scalar(
            "UPDATE invites i SET used_at = now()
             FROM accounts a
             WHERE i.account_id = a.id AND a.status = 'active'
               AND i.code_hash = $1 AND i.used_at IS NULL AND i.expires_at > now()
             RETURNING i.account_id",
        )
        .bind(secrets::invite_code_hash(code))
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(refused)?,
        (None, Some(username)) => {
            sqlx::query_scalar("SELECT id FROM accounts WHERE username = $1 AND status = 'active'")
                .bind(username)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(refused)?
        }
        _ => return Err(ApiError::bad_request("provide exactly one of invite_code or username")),
    };

    let device_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO devices (id, account_id, display_name, signing_key, olm_identity_key, olm_fingerprint_key)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (signing_key) DO NOTHING",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(display_name)
    .bind(signing_key.as_slice())
    .bind(olm_identity_key.as_slice())
    .bind(olm_fingerprint_key.as_slice())
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("device-key-in-use"));
    }
    tx.commit().await?;
    tracing::info!(%device_id, %account_id, "device enrolled, pending approval");
    Ok(Json(EnrollResponse { device_id, status: DeviceStatus::Pending }))
}

/// Exchanges a signed challenge for a short-lived token. Pending devices get a
/// session too, but it only grants access to the status endpoint.
pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let mut tx = state.pool.begin().await?;
    auth::consume_challenge(&mut *tx, &req.nonce.0, Purpose::Device).await?;

    let row = sqlx::query(
        "SELECT d.signing_key, d.status, a.status AS account_status
         FROM devices d JOIN accounts a ON a.id = d.account_id WHERE d.id = $1",
    )
    .bind(req.device_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::forbidden("invalid-signature"))?;
    let signing_key: Vec<u8> = row.try_get("signing_key")?;
    if !signing::verify(&signing_key, &signing::device_auth_message(&req.nonce.0, req.device_id), &req.signature.0) {
        return Err(ApiError::forbidden("invalid-signature"));
    }
    let status: String = row.try_get("status")?;
    let account_status: String = row.try_get("account_status")?;
    if account_status != "active" {
        return Err(ApiError::forbidden("account-disabled"));
    }
    if status != "pending" && status != "active" {
        return Err(ApiError::forbidden("device-not-active"));
    }

    let (token, hash) = secrets::new_token();
    sqlx::query("INSERT INTO sessions (token_hash, device_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash)
        .bind(req.device_id)
        .bind(Utc::now() + auth::DEVICE_SESSION_TTL)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(SessionResponse { token, expires_in_secs: auth::DEVICE_SESSION_TTL.num_seconds() as u64 }))
}

pub async fn status(device: AuthDevice) -> Json<DeviceStatusResponse> {
    Json(DeviceStatusResponse { device_id: device.device_id, status: device.status })
}

/// Lists the caller's own devices.
pub async fn own_devices(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
) -> ApiResult<Json<Vec<DeviceInfo>>> {
    let rows = sqlx::query(
        "SELECT id, display_name, status, olm_fingerprint_key, created_at
         FROM devices WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(device.account_id)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(DeviceInfo {
                device_id: row.try_get("id")?,
                display_name: row.try_get("display_name")?,
                status: DeviceStatus::parse(row.try_get("status")?).ok_or_else(ApiError::internal)?,
                olm_fingerprint_key: B64(row.try_get("olm_fingerprint_key")?),
                created_at: row.try_get::<DateTime<Utc>, _>("created_at")?.to_rfc3339(),
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}
