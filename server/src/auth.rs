//! Challenges, bearer-token extractors and session lifetimes (TDD §5.3, §10.2).

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use chrono::{Duration, Utc};
use sqlx::{PgExecutor, Row};
use ssm_proto::api::DeviceStatus;
use uuid::Uuid;

use crate::AppState;
use crate::error::{ApiError, ApiResult};
use crate::secrets;

pub const CHALLENGE_TTL: Duration = Duration::seconds(60);
pub const DEVICE_SESSION_TTL: Duration = Duration::minutes(15);
pub const ADMIN_SESSION_TTL: Duration = Duration::minutes(10);

#[derive(Debug, Clone, Copy)]
pub enum Purpose {
    Enroll,
    Device,
    Admin,
    AdminConfirm,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Device => "device",
            Self::Admin => "admin",
            Self::AdminConfirm => "admin_confirm",
        }
    }
}

pub async fn issue_challenge(db: impl PgExecutor<'_>, purpose: Purpose) -> ApiResult<Vec<u8>> {
    let nonce = secrets::random_bytes::<{ secrets::NONCE_LEN }>().to_vec();
    sqlx::query("INSERT INTO auth_challenges (nonce, purpose, expires_at) VALUES ($1, $2, $3)")
        .bind(&nonce)
        .bind(purpose.as_str())
        .bind(Utc::now() + CHALLENGE_TTL)
        .execute(db)
        .await?;
    Ok(nonce)
}

/// Consumes a nonce exactly once. Expired, unknown or reused nonces fail.
pub async fn consume_challenge(db: impl PgExecutor<'_>, nonce: &[u8], purpose: Purpose) -> ApiResult<()> {
    let consumed = sqlx::query(
        "DELETE FROM auth_challenges WHERE nonce = $1 AND purpose = $2 AND expires_at > now() RETURNING nonce",
    )
    .bind(nonce)
    .bind(purpose.as_str())
    .fetch_optional(db)
    .await?;
    consumed.map(|_| ()).ok_or_else(|| ApiError::forbidden("invalid-challenge"))
}

fn bearer_token(parts: &Parts) -> ApiResult<&str> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)
}

/// A device with a valid session that is `pending` or `active`. The status is
/// re-read on every request, so disabling or revoking takes effect at once.
#[derive(Debug, Clone, Copy)]
pub struct AuthDevice {
    pub device_id: Uuid,
    pub account_id: Uuid,
    pub status: DeviceStatus,
}

impl FromRequestParts<AppState> for AuthDevice {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let hash = secrets::token_hash(bearer_token(parts)?);
        let row = sqlx::query(
            "SELECT d.id, d.account_id, d.status, a.status AS account_status
             FROM sessions s
             JOIN devices d ON d.id = s.device_id
             JOIN accounts a ON a.id = d.account_id
             WHERE s.token_hash = $1 AND s.expires_at > now()",
        )
        .bind(hash)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::unauthorized)?;

        let account_status: String = row.try_get("account_status")?;
        let status = DeviceStatus::parse(row.try_get("status")?).ok_or_else(ApiError::internal)?;
        if account_status != "active" {
            return Err(ApiError::forbidden("account-disabled"));
        }
        if !matches!(status, DeviceStatus::Pending | DeviceStatus::Active) {
            return Err(ApiError::forbidden("device-not-active"));
        }
        Ok(Self { device_id: row.try_get("id")?, account_id: row.try_get("account_id")?, status })
    }
}

/// An approved (`active`) device. Pending devices are refused.
#[derive(Debug, Clone, Copy)]
pub struct ActiveDevice(pub AuthDevice);

impl FromRequestParts<AppState> for ActiveDevice {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let device = AuthDevice::from_request_parts(parts, state).await?;
        if device.status != DeviceStatus::Active {
            return Err(ApiError::forbidden("device-pending"));
        }
        Ok(Self(device))
    }
}

/// An admin with a valid admin session, active admin key and admin role.
#[derive(Debug, Clone, Copy)]
pub struct AdminAuth {
    pub admin_key_id: Uuid,
    pub account_id: Uuid,
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let hash = secrets::token_hash(bearer_token(parts)?);
        let row = sqlx::query(
            "SELECT k.id, k.account_id
             FROM admin_sessions s
             JOIN admin_keys k ON k.id = s.admin_key_id
             JOIN accounts a ON a.id = k.account_id
             WHERE s.token_hash = $1 AND s.expires_at > now()
               AND k.status = 'active' AND a.role = 'admin' AND a.status = 'active'",
        )
        .bind(hash)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
        Ok(Self { admin_key_id: row.try_get("id")?, account_id: row.try_get("account_id")? })
    }
}

/// Removes expired challenges and sessions.
pub async fn purge_expired(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM auth_challenges WHERE expires_at <= now()").execute(db).await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at <= now()").execute(db).await?;
    sqlx::query("DELETE FROM admin_sessions WHERE expires_at <= now()").execute(db).await?;
    Ok(())
}
