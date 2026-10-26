//! ssm-server: self-hosted E2EE messenger backend.

pub mod accounts;
pub mod audit;
pub mod auth;
pub mod devices;
pub mod error;
pub mod hub;
pub mod ratelimit;
pub mod routes;
pub mod secrets;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use sqlx::PgPool;

use crate::hub::Hub;
use crate::ratelimit::RateLimiter;
use crate::routes::{admin, device, events, keys};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub hub: Arc<Hub>,
}

impl AppState {
    pub fn new(pool: PgPool) -> Self {
        Self { pool, hub: Arc::new(Hub::default()) }
    }
}

/// Unauthenticated endpoints: 30 requests per minute and IP.
pub fn router(state: AppState) -> Router {
    let unauthenticated_limit = RateLimiter::new(30, Duration::from_secs(60));

    let public = Router::new()
        .route("/v1/devices/enroll/challenge", post(device::enroll_challenge))
        .route("/v1/devices/enroll", post(device::enroll))
        .route("/v1/auth/challenge", post(device::session_challenge))
        .route("/v1/auth/session", post(device::create_session))
        .route("/v1/admin/auth/challenge", post(admin::auth_challenge))
        .route("/v1/admin/auth/session", post(admin::create_session))
        .layer(from_fn_with_state(unauthenticated_limit, ratelimit::limit));

    let authenticated = Router::new()
        .route("/v1/devices/status", get(device::status))
        .route("/v1/devices", get(device::own_devices))
        .route("/v1/keys/one-time", post(keys::upload))
        .route("/v1/keys/claim", post(keys::claim))
        .route("/v1/accounts/by-username/{username}", get(keys::lookup_account))
        .route("/v1/accounts/{id}/devices", get(keys::account_devices))
        .route("/v1/to-device", post(keys::send_to_device))
        .route("/v1/events", get(events::list))
        .route("/v1/ws", get(events::websocket))
        .route("/v1/admin/confirm/challenge", post(admin::confirm_challenge))
        .route("/v1/admin/accounts", get(admin::list_accounts).post(admin::create_account))
        .route("/v1/admin/accounts/{id}/invites", post(admin::create_invite))
        .route("/v1/admin/devices", get(admin::list_devices))
        .route("/v1/admin/devices/{id}/{action}", post(admin::device_action))
        .route("/v1/admin/audit-events", get(admin::audit_events));

    Router::new().route("/healthz", get(|| async { "ok" })).merge(public).merge(authenticated).with_state(state)
}

/// Periodically removes expired challenges and sessions.
pub fn spawn_maintenance(pool: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(err) = auth::purge_expired(&pool).await {
                tracing::warn!(error = %err, "purging expired sessions failed");
            }
            if let Err(err) = devices::purge_expired_events(&pool).await {
                tracing::warn!(error = %err, "purging expired events failed");
            }
        }
    });
}
