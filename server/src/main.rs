//! Server entry point. Configuration comes from the environment:
//!
//! - `SSM_DATABASE_URL` (required), e.g. `postgres://ssm@localhost/ssm`
//! - `SSM_BIND` (default `127.0.0.1:8080`); TLS is terminated by a reverse proxy
//! - `SSM_BACKUP_RETENTION_DAYS` (default 30): how long backups keep deleted data
//! - `RUST_LOG` (default `info`)

use std::net::SocketAddr;

use sqlx::postgres::PgPoolOptions;
use ssm_server::{AppState, Config, MIGRATOR, router, spawn_maintenance};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let database_url = std::env::var("SSM_DATABASE_URL").map_err(|_| "SSM_DATABASE_URL is not set")?;
    let bind: SocketAddr = std::env::var("SSM_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into()).parse()?;

    let mut config = Config::default();
    if let Ok(days) = std::env::var("SSM_BACKUP_RETENTION_DAYS") {
        config.backup_retention_days = days.parse().map_err(|_| "SSM_BACKUP_RETENTION_DAYS must be a number")?;
    }

    let pool = PgPoolOptions::new().max_connections(20).connect(&database_url).await?;
    MIGRATOR.run(&pool).await?;
    spawn_maintenance(pool.clone());
    let state = AppState::with_config(pool, config);
    let resumed = ssm_server::massdelete::resume_interrupted(&state).await?;
    if resumed > 0 {
        tracing::info!(resumed, "resumed interrupted mass deletions");
    }

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "ssm-server listening");
    axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
