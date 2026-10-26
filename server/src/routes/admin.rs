//! Admin API (FR-016 – FR-020, ADR-0006). Every handler authorizes through
//! `AdminAuth`; state-changing actions are written to the audit log.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use ssm_proto::api::{
    AccountInfo, AdminDeviceInfo, AdminSessionRequest, AuditEvent, ChallengeResponse, ConfirmRequest, ContentSummary,
    CreateAccountRequest, DeleteJobInfo, DeleteJobStatus, DeviceAction, DeviceStatus, InviteResponse,
    MassDeleteRequest, SessionResponse,
};
use ssm_proto::{B64, signing};
use uuid::Uuid;

use super::conversations::job_info;
use super::device::challenge_response;
use crate::audit::{self, Entry};
use crate::auth::{self, AdminAuth, Purpose};
use crate::conversations::{self, NewJob};
use crate::devices::{self, ActionOutcome};
use crate::error::{ApiError, ApiResult};
use crate::{AppState, secrets};
use crate::{accounts, massdelete};

fn rfc3339(row: &sqlx::postgres::PgRow, column: &str) -> ApiResult<String> {
    Ok(row.try_get::<DateTime<Utc>, _>(column)?.to_rfc3339())
}

pub async fn auth_challenge(State(state): State<AppState>) -> ApiResult<Json<ChallengeResponse>> {
    let nonce = auth::issue_challenge(&state.pool, Purpose::Admin).await?;
    Ok(Json(challenge_response(nonce)))
}

pub async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<AdminSessionRequest>,
) -> ApiResult<Json<SessionResponse>> {
    let mut tx = state.pool.begin().await?;
    auth::consume_challenge(&mut *tx, &req.nonce.0, Purpose::Admin).await?;
    let public_key: Vec<u8> = sqlx::query_scalar(
        "SELECT k.public_key FROM admin_keys k JOIN accounts a ON a.id = k.account_id
         WHERE k.id = $1 AND k.status = 'active' AND a.role = 'admin' AND a.status = 'active'",
    )
    .bind(req.admin_key_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::forbidden("invalid-signature"))?;
    if !signing::verify(&public_key, &signing::admin_auth_message(&req.nonce.0, req.admin_key_id), &req.signature.0) {
        return Err(ApiError::forbidden("invalid-signature"));
    }
    let (token, hash) = secrets::new_token();
    sqlx::query("INSERT INTO admin_sessions (token_hash, admin_key_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash)
        .bind(req.admin_key_id)
        .bind(Utc::now() + auth::ADMIN_SESSION_TTL)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(SessionResponse { token, expires_in_secs: auth::ADMIN_SESSION_TTL.num_seconds() as u64 }))
}

/// Nonce for confirming a destructive action; requires an admin session.
pub async fn confirm_challenge(State(state): State<AppState>, _admin: AdminAuth) -> ApiResult<Json<ChallengeResponse>> {
    let nonce = auth::issue_challenge(&state.pool, Purpose::AdminConfirm).await?;
    Ok(Json(challenge_response(nonce)))
}

/// Checks the fresh confirmation signature of the logged-in admin key.
async fn verify_confirmation(
    conn: &mut sqlx::PgConnection,
    admin: AdminAuth,
    confirm: Option<&ConfirmRequest>,
    action: &str,
    target: &str,
) -> ApiResult<()> {
    let confirm = confirm.ok_or_else(|| ApiError::forbidden("confirmation-required"))?;
    auth::consume_challenge(&mut *conn, &confirm.nonce.0, Purpose::AdminConfirm).await?;
    let public_key: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM admin_keys WHERE id = $1")
        .bind(admin.admin_key_id)
        .fetch_one(&mut *conn)
        .await?;
    let message = signing::admin_confirm_message(&confirm.nonce.0, action, target);
    if !signing::verify(&public_key, &message, &confirm.signature.0) {
        return Err(ApiError::forbidden("invalid-confirmation"));
    }
    Ok(())
}

pub async fn create_account(
    State(state): State<AppState>,
    admin: AdminAuth,
    Json(req): Json<CreateAccountRequest>,
) -> ApiResult<Json<InviteResponse>> {
    if !accounts::is_valid_username(&req.username) {
        return Err(ApiError::bad_request("username must be 3-32 characters of [a-z0-9_.-]"));
    }
    let mut tx = state.pool.begin().await?;
    let account_id = accounts::create_account(&mut tx, &req.username, "user")
        .await?
        .ok_or_else(|| ApiError::conflict("username-taken"))?;
    let (invite_code, expires_at) = accounts::create_invite(&mut tx, account_id).await?;
    audit::append(
        &mut tx,
        Entry {
            admin_account_id: Some(admin.account_id),
            action: "account.create",
            target: &format!("account:{account_id}"),
            result: "ok",
            correlation_id: Uuid::new_v4(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(InviteResponse { account_id, invite_code, expires_at: expires_at.to_rfc3339() }))
}

pub async fn create_invite(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
) -> ApiResult<Json<InviteResponse>> {
    let mut tx = state.pool.begin().await?;
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1 AND status = 'active'")
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?;
    exists.ok_or_else(ApiError::not_found)?;
    let (invite_code, expires_at) = accounts::create_invite(&mut tx, account_id).await?;
    audit::append(
        &mut tx,
        Entry {
            admin_account_id: Some(admin.account_id),
            action: "invite.create",
            target: &format!("account:{account_id}"),
            result: "ok",
            correlation_id: Uuid::new_v4(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(InviteResponse { account_id, invite_code, expires_at: expires_at.to_rfc3339() }))
}

pub async fn list_accounts(State(state): State<AppState>, _admin: AdminAuth) -> ApiResult<Json<Vec<AccountInfo>>> {
    let rows = sqlx::query("SELECT id, username, role, status, created_at FROM accounts ORDER BY username")
        .fetch_all(&state.pool)
        .await?;
    rows.iter()
        .map(|row| {
            Ok(AccountInfo {
                account_id: row.try_get("id")?,
                username: row.try_get("username")?,
                role: row.try_get("role")?,
                status: row.try_get("status")?,
                created_at: rfc3339(row, "created_at")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

#[derive(Debug, Deserialize)]
pub struct DeviceFilter {
    status: Option<String>,
}

pub async fn list_devices(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(filter): Query<DeviceFilter>,
) -> ApiResult<Json<Vec<AdminDeviceInfo>>> {
    let status = match filter.status.as_deref() {
        Some(s) => Some(DeviceStatus::parse(s).ok_or_else(|| ApiError::bad_request("unknown status"))?.as_str()),
        None => None,
    };
    let rows = sqlx::query(
        "SELECT d.id, d.account_id, a.username, d.display_name, d.status, d.olm_fingerprint_key, d.created_at
         FROM devices d JOIN accounts a ON a.id = d.account_id
         WHERE $1::text IS NULL OR d.status = $1
         ORDER BY d.created_at",
    )
    .bind(status)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(AdminDeviceInfo {
                device_id: row.try_get("id")?,
                account_id: row.try_get("account_id")?,
                username: row.try_get("username")?,
                display_name: row.try_get("display_name")?,
                status: DeviceStatus::parse(row.try_get("status")?).ok_or_else(ApiError::internal)?,
                olm_fingerprint_key: B64(row.try_get("olm_fingerprint_key")?),
                created_at: rfc3339(row, "created_at")?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

/// approve | reject | disable | enable | revoke. Revoke needs a confirmation
/// signature. Leaving `active` ends all sessions of the device immediately;
/// revoked and rejected devices are deleted completely.
pub async fn device_action(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path((device_id, action)): Path<(Uuid, String)>,
    body: Bytes,
) -> ApiResult<Json<AdminDeviceInfo>> {
    let action = DeviceAction::parse(&action).ok_or_else(ApiError::not_found)?;
    let confirm: Option<ConfirmRequest> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("invalid confirmation body"))?)
    };
    let target = format!("device:{device_id}");
    let mut tx = state.pool.begin().await?;
    if action.is_destructive() {
        verify_confirmation(&mut tx, admin, confirm.as_ref(), action.as_str(), &target).await?;
    }
    // Read before the action: revoked and rejected devices are deleted.
    let row = sqlx::query(
        "SELECT d.id, d.account_id, a.username, d.display_name, d.status, d.olm_fingerprint_key, d.created_at
         FROM devices d JOIN accounts a ON a.id = d.account_id WHERE d.id = $1",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::not_found)?;
    let next = match devices::apply_action(&mut tx, device_id, action, Some(admin.account_id), "").await? {
        ActionOutcome::Changed(next) => next,
        ActionOutcome::NotFound => return Err(ApiError::not_found()),
        ActionOutcome::InvalidTransition(current) => {
            tx.commit().await?;
            return Err(ApiError::conflict("invalid-transition").with_detail(format!(
                "cannot {} a {} device",
                action.as_str(),
                current.as_str()
            )));
        }
    };

    tx.commit().await?;
    if next != DeviceStatus::Active {
        state.close_device(device_id);
    }
    tracing::info!(%device_id, action = action.as_str(), "admin device action");

    Ok(Json(AdminDeviceInfo {
        device_id,
        account_id: row.try_get("account_id")?,
        username: row.try_get("username")?,
        display_name: row.try_get("display_name")?,
        status: next,
        olm_fingerprint_key: B64(row.try_get("olm_fingerprint_key")?),
        created_at: rfc3339(&row, "created_at")?,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    before: Option<i64>,
    limit: Option<i64>,
}

/// Newest first; page with `before=<id>`.
pub async fn audit_events(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEvent>>> {
    let limit = query.limit.unwrap_or(100).clamp(1, 100);
    let rows = sqlx::query(
        "SELECT id, admin_account_id, action, target, result, correlation_id, created_at, hash
         FROM admin_audit_events
         WHERE $1::bigint IS NULL OR id < $1
         ORDER BY id DESC LIMIT $2",
    )
    .bind(query.before)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(AuditEvent {
                id: row.try_get("id")?,
                admin_account_id: row.try_get("admin_account_id")?,
                action: row.try_get("action")?,
                target: row.try_get("target")?,
                result: row.try_get("result")?,
                correlation_id: row.try_get("correlation_id")?,
                created_at: rfc3339(row, "created_at")?,
                hash: hex::encode(row.try_get::<Vec<u8>, _>("hash")?),
            })
        })
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

pub const MASS_DELETE_ACTION: &str = "delete-all-content";

/// Scope shown to the admin before confirming a mass deletion.
pub async fn content_summary(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(account_id): Path<Uuid>,
) -> ApiResult<Json<ContentSummary>> {
    let username: String = sqlx::query_scalar("SELECT username FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(ApiError::not_found)?;
    let (messages, conversations): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(DISTINCT conversation_id) FROM messages
         WHERE sender_account_id = $1 AND kind = 'encrypted' AND deleted_at IS NULL AND expires_at > now()",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(ContentSummary { account_id, username, messages, conversations }))
}

/// Deletes everything an account has sent, for everyone (FR-018). Requires a
/// confirmation signature; runs asynchronously; idempotent per operation id.
pub async fn delete_all_content(
    State(state): State<AppState>,
    admin: AdminAuth,
    Path(account_id): Path<Uuid>,
    Json(req): Json<MassDeleteRequest>,
) -> ApiResult<Json<DeleteJobInfo>> {
    let target = format!("account:{account_id}");
    let mut tx = state.pool.begin().await?;
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM delete_jobs WHERE requested_by = $1 AND operation_id = $2")
            .bind(admin.account_id)
            .bind(req.operation_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(job_id) = existing {
        return Ok(Json(job_info(&mut tx, job_id).await?));
    }
    let confirm = ConfirmRequest { nonce: req.nonce, signature: req.signature };
    verify_confirmation(&mut tx, admin, Some(&confirm), MASS_DELETE_ACTION, &target).await?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE id = $1").bind(account_id).fetch_optional(&mut *tx).await?;
    exists.ok_or_else(ApiError::not_found)?;

    let job = NewJob {
        id: Uuid::new_v4(),
        operation_id: req.operation_id,
        requested_by: Some(admin.account_id),
        requested_by_admin: true,
        scope: serde_json::json!({ "type": "account", "account_id": account_id }),
    };
    conversations::insert_job(&mut tx, &job, DeleteJobStatus::InProgress).await?;
    audit::append(
        &mut tx,
        Entry {
            admin_account_id: Some(admin.account_id),
            action: "account.delete_all_content",
            target: &target,
            result: "started",
            correlation_id: job.id,
        },
    )
    .await?;
    let info = job_info(&mut tx, job.id).await?;
    tx.commit().await?;
    tokio::spawn(massdelete::run(state.clone(), job.id, account_id, Some(admin.account_id)));
    Ok(Json(info))
}

pub async fn delete_job(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(job_id): Path<Uuid>,
) -> ApiResult<Json<DeleteJobInfo>> {
    let mut conn = state.pool.acquire().await?;
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM delete_jobs WHERE id = $1").bind(job_id).fetch_optional(&mut *conn).await?;
    exists.ok_or_else(ApiError::not_found)?;
    Ok(Json(job_info(&mut conn, job_id).await?))
}
