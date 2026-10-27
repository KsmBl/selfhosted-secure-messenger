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
pub mod media;
pub mod netconfig;
pub mod push;
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
use crate::routes::{admin, conversations as conv, device, events, keys, media as media_routes};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub hub: Arc<Hub>,
    pub config: Arc<Config>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Accept clients from public internet addresses. Off by default: the
    /// server speaks plain HTTP and is meant for loopback (behind the TLS
    /// proxy) and private networks (LAN, VPN). See [`ratelimit::local_only`].
    pub allow_public_clients: bool,
    /// Set in processes other than the server (TUI): wake-ups and
    /// disconnects are forwarded to the server through PostgreSQL.
    pub remote_hub: bool,
    pub push: push::PushConfig,
    /// Where encrypted media files are stored.
    pub media_dir: std::path::PathBuf,
    pub max_media_bytes: usize,
}

impl Config {
    /// Configuration from the `SSM_*` environment (see `ssm-server --help`).
    pub fn from_env() -> Result<Config, Box<dyn std::error::Error>> {
        let mut config = Config::default();
        let flag = |name: &str| std::env::var(name).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        config.push.allow_private = flag("SSM_PUSH_ALLOW_PRIVATE");
        config.push.allow_http = flag("SSM_PUSH_ALLOW_HTTP");
        config.push.fcm_service_account = std::env::var_os("SSM_FCM_SERVICE_ACCOUNT").map(Into::into);
        config.allow_public_clients = flag("SSM_ALLOW_PUBLIC_CLIENTS");
        // systemd sets STATE_DIRECTORY for StateDirectory=ssm (/var/lib/ssm).
        config.media_dir = match (std::env::var_os("SSM_MEDIA_DIR"), std::env::var_os("STATE_DIRECTORY")) {
            (Some(dir), _) => dir.into(),
            (None, Some(state)) => std::path::PathBuf::from(state).join("media"),
            (None, None) => {
                let home = std::env::var_os("HOME").unwrap_or_default();
                std::path::PathBuf::from(home).join(".local/share/ssm-server/media")
            }
        };
        if let Ok(mb) = std::env::var("SSM_MAX_MEDIA_MB") {
            config.max_media_bytes =
                mb.parse::<usize>().map_err(|_| "SSM_MAX_MEDIA_MB must be a number")? * 1024 * 1024;
        }
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allow_public_clients: false,
            remote_hub: false,
            push: push::PushConfig::default(),
            media_dir: std::env::temp_dir().join("ssm-media"),
            max_media_bytes: 64 * 1024 * 1024,
        }
    }
}

impl AppState {
    pub fn new(pool: PgPool) -> Self {
        Self::with_config(pool, Config::default())
    }

    pub fn with_config(pool: PgPool, config: Config) -> Self {
        let hub = Arc::new(Hub::default());
        // Other processes (TUI) forward their wake-ups to the server, which
        // sends the pushes; only the server runs the push worker.
        if !config.remote_hub {
            hub.set_pusher(push::spawn(pool.clone(), config.push.clone()));
        }
        Self { pool, hub, config: Arc::new(config) }
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

/// Rate limits per minute: unauthenticated endpoints 30 per IP; devices 600
/// requests and 60 media uploads per session; admins 120 per session.
pub fn router(state: AppState) -> Router {
    let minute = Duration::from_secs(60);
    let unauthenticated_limit = RateLimiter::new(30, minute);
    let device_limit = RateLimiter::<ratelimit::Caller>::new(600, minute);
    let media_limit = RateLimiter::<ratelimit::Caller>::new(60, minute);
    let admin_limit = RateLimiter::<ratelimit::Caller>::new(120, minute);

    let public = Router::new()
        .route("/v1/devices/enroll/challenge", post(device::enroll_challenge))
        .route("/v1/devices/enroll", post(device::enroll))
        .route("/v1/auth/challenge", post(device::session_challenge))
        .route("/v1/auth/session", post(device::create_session))
        .route("/v1/admin/auth/challenge", post(admin::auth_challenge))
        .route("/v1/admin/auth/session", post(admin::create_session))
        .route("/v1/admin/keys/lookup", get(admin::lookup_admin_key))
        .layer(from_fn_with_state(unauthenticated_limit, ratelimit::limit));

    let devices = Router::new()
        .route("/v1/devices/status", get(device::status))
        .route("/v1/devices", get(device::own_devices))
        .route("/v1/devices/self", delete(device::remove_self))
        .route("/v1/push-endpoint", put(device::set_push_endpoint).delete(device::remove_push_endpoint))
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
        .route("/v1/conversations/{id}/delete-messages", post(conv::delete_messages))
        .route(
            "/v1/conversations/{id}/media",
            post(media_routes::upload)
                .layer(axum::extract::DefaultBodyLimit::max(state.config.max_media_bytes + 64))
                .layer(from_fn_with_state(media_limit, ratelimit::limit_per_session)),
        )
        .route("/v1/media/{id}", get(media_routes::download))
        .route("/v1/delete-jobs/{id}", get(conv::delete_job))
        .route("/v1/events", get(events::list))
        .route("/v1/ws", get(events::websocket))
        .route("/v1/notifications/hint", get(events::notification_hint))
        .layer(from_fn_with_state(device_limit, ratelimit::limit_per_session));

    let admins = Router::new()
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
        .layer(from_fn_with_state(admin_limit, ratelimit::limit_per_session));

    let allow_public = state.config.allow_public_clients;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(public)
        .merge(devices)
        .merge(admins)
        .layer(axum::middleware::from_fn(move |request, next| ratelimit::local_only(allow_public, request, next)))
        .with_state(state)
}

/// Periodic housekeeping: expired challenges, sessions, events and
/// messages, media files of deleted messages, and interrupted mass deletions.
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
            if let Err(err) = crate::media::purge(&state).await {
                tracing::warn!(error = %err, "media purge failed");
            }
            if let Err(err) = massdelete::resume_interrupted(&state).await {
                tracing::warn!(error = %err, "resuming mass deletions failed");
            }
        }
    });
}
