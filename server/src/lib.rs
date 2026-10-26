//! ssm-server: self-hosted E2EE messenger backend.

pub mod accounts;
pub mod audit;
pub mod auth;
pub mod conversations;
pub mod devices;
pub mod error;
pub mod hub;
pub mod manage;
pub mod massdelete;
pub mod ratelimit;
pub mod routes;
pub mod secrets;
pub mod tui;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post, put};
use sqlx::PgPool;

use crate::hub::Hub;
use crate::ratelimit::RateLimiter;
use crate::routes::{admin, conversations as conv, device, events, keys};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub hub: Arc<Hub>,
    pub config: Arc<Config>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// How long backups keep deleted data; delete jobs stay
    /// `backup_purge_pending` for this long (FR-010).
    pub backup_retention_days: i32,
    /// Set in processes other than the server (TUI): wake-ups and
    /// disconnects are forwarded to the server through PostgreSQL.
    pub remote_hub: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { backup_retention_days: 30, remote_hub: false }
    }
}

impl AppState {
    pub fn new(pool: PgPool) -> Self {
        Self::with_config(pool, Config::default())
    }

    pub fn with_config(pool: PgPool, config: Config) -> Self {
        Self { pool, hub: Arc::new(Hub::default()), config: Arc::new(config) }
    }

    /// Sends sync hints after a commit.
    pub fn wake(&self, woken: &[(uuid::Uuid, i64)]) {
        for &(device_id, seq) in woken {
            self.hub.sync(device_id, seq);
        }
        if self.config.remote_hub {
            let events: Vec<_> = woken.iter().map(|&(device_id, seq)| hub::HubEvent::Sync { device_id, seq }).collect();
            self.publish(events);
        }
    }

    /// Ends the device's WebSocket connections.
    pub fn close_device(&self, device_id: uuid::Uuid) {
        self.hub.close(device_id);
        if self.config.remote_hub {
            self.publish(vec![hub::HubEvent::Close { device_id }]);
        }
    }

    fn publish(&self, events: Vec<hub::HubEvent>) {
        let pool = self.pool.clone();
        tokio::spawn(async move {
            if let Err(err) = hub::publish(&pool, &events).await {
                tracing::warn!(error = %err, "forwarding hub events failed");
            }
        });
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
        .route("/v1/admin/keys/lookup", get(admin::lookup_admin_key))
        .layer(from_fn_with_state(unauthenticated_limit, ratelimit::limit));

    let authenticated = Router::new()
        .route("/v1/devices/status", get(device::status))
        .route("/v1/devices", get(device::own_devices))
        .route("/v1/devices/self", delete(device::remove_self))
        .route("/v1/keys/one-time", post(keys::upload))
        .route("/v1/keys/claim", post(keys::claim))
        .route("/v1/accounts/by-username/{username}", get(keys::lookup_account))
        .route("/v1/accounts/{id}/devices", get(keys::account_devices))
        .route("/v1/to-device", post(keys::send_to_device))
        .route("/v1/conversations", get(conv::list).post(conv::create))
        .route("/v1/conversations/{id}", get(conv::get))
        .route("/v1/conversations/{id}/members", post(conv::add_member))
        .route("/v1/conversations/{id}/members/{account_id}", delete(conv::remove_member))
        .route("/v1/conversations/{id}/retention", put(conv::set_retention))
        .route("/v1/conversations/{id}/messages", get(conv::messages).post(conv::send))
        .route("/v1/messages/{id}/delete-for-all", post(conv::delete_for_all))
        .route("/v1/delete-jobs/{id}", get(conv::delete_job))
        .route("/v1/events", get(events::list))
        .route("/v1/ws", get(events::websocket))
        .route("/v1/admin/confirm/challenge", post(admin::confirm_challenge))
        .route("/v1/admin/accounts", get(admin::list_accounts).post(admin::create_account))
        .route("/v1/admin/accounts/{id}/invites", post(admin::create_invite))
        .route("/v1/admin/devices", get(admin::list_devices))
        .route("/v1/admin/devices/{id}/{action}", post(admin::device_action))
        .route("/v1/admin/accounts/{id}/content-summary", get(admin::content_summary))
        .route("/v1/admin/accounts/{id}/delete-all-content", post(admin::delete_all_content))
        .route("/v1/admin/delete-jobs/{id}", get(admin::delete_job))
        .route("/v1/admin/delete-jobs", get(admin::list_jobs))
        .route("/v1/admin/overview", get(admin::overview))
        .route("/v1/admin/accounts/{id}/status", post(admin::set_account_status))
        .route("/v1/admin/accounts/{id}/role", post(admin::set_account_role))
        .route("/v1/admin/accounts/{id}/admin-keys", post(admin::add_admin_key))
        .route("/v1/admin/accounts/{id}/delete", post(admin::delete_account))
        .route("/v1/admin/audit-events", get(admin::audit_events))
        .route("/v1/notifications/hint", get(events::notification_hint));

    Router::new().route("/healthz", get(|| async { "ok" })).merge(public).merge(authenticated).with_state(state)
}

/// Periodic housekeeping: expired challenges, sessions, events and
/// messages, backup purge status, and interrupted mass deletions.
pub fn spawn_maintenance(state: AppState) {
    tokio::spawn(async move {
        let pool = state.pool.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(err) = auth::purge_expired(&pool).await {
                tracing::warn!(error = %err, "purging expired sessions failed");
            }
            if let Err(err) = devices::purge_expired_events(&pool).await {
                tracing::warn!(error = %err, "purging expired events failed");
            }
            if let Err(err) = conversations::run_expiry(&pool).await {
                tracing::warn!(error = %err, "message expiry failed");
            }
            if let Err(err) = massdelete::resume_interrupted(&state).await {
                tracing::warn!(error = %err, "resuming mass deletions failed");
            }
        }
    });
}
