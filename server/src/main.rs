//! Server entry point. Configuration comes from the environment:
//!
//! - `SSM_DATABASE_URL` (required), e.g. `postgres://ssm@localhost/ssm`
//! - `SSM_BIND` (default `127.0.0.1:8080`); TLS is terminated by a reverse proxy
//! - `RUST_LOG` (default `info`)

use std::net::SocketAddr;

use sqlx::postgres::PgPoolOptions;
use ssm_server::{AppState, MIGRATOR, router, spawn_maintenance};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let database_url = std::env::var("SSM_DATABASE_URL").map_err(|_| "SSM_DATABASE_URL is not set")?;
    let bind: SocketAddr = std::env::var("SSM_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into()).parse()?;

    let pool = PgPoolOptions::new().max_connections(20).connect(&database_url).await?;
    MIGRATOR.run(&pool).await?;
    spawn_maintenance(pool.clone());

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "ssm-server listening");
    axum::serve(listener, router(AppState::new(pool)).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
