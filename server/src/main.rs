//! Server entry point.
//!
//! - `ssm-server` / `ssm-server serve`: run the API server
//! - `ssm-server tui`: terminal management interface (on the server host)
//!
//! Configuration comes from the environment:
//!
//! - `SSM_DATABASE_URL` (required), e.g. `postgres://ssm@localhost/ssm`
//! - `SSM_BIND` (default `127.0.0.1:8080`); TLS is terminated by a reverse proxy
//! - `SSM_BACKUP_RETENTION_DAYS` (default 30): how long backups keep deleted data
//! - `SSM_PUSH_ALLOW_PRIVATE=1`: allow UnifiedPush endpoints on private addresses
//!   (a self-hosted ntfy in the LAN); `SSM_PUSH_ALLOW_HTTP=1` allows http://
//! - `SSM_FCM_SERVICE_ACCOUNT`: Firebase service account JSON for the FCM fallback
//! - `SSM_MEDIA_DIR`: encrypted media files (default `$STATE_DIRECTORY/media`,
//!   i.e. /var/lib/ssm/media under systemd); `SSM_MAX_MEDIA_MB` (default 64)
//! - `SSM_DELETION_JOURNAL`: IDs of deleted messages/accounts, replayed after
//!   restoring a backup (default `deletions.log` next to the media directory)
//! - `RUST_LOG` (default `info`)

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;
use ssm_server::{AppState, Config, MIGRATOR, router, spawn_maintenance};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "ssm-server", about = "Self-hosted secure messenger server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the API server (default).
    Serve,
    /// Manage devices, accounts, delete jobs and the audit log in the terminal.
    Tui,
}

type MainResult = Result<(), Box<dyn std::error::Error>>;

async fn connect(max_connections: u32) -> Result<sqlx::PgPool, Box<dyn std::error::Error>> {
    let database_url = std::env::var("SSM_DATABASE_URL").map_err(|_| "SSM_DATABASE_URL is not set")?;
    let pool = PgPoolOptions::new().max_connections(max_connections).connect(&database_url).await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

#[tokio::main]
async fn main() -> MainResult {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Tui => {
            let mut config = Config::from_env()?;
            config.remote_hub = true;
            let state = AppState::with_config(connect(5).await?, config);
            ssm_server::tui::run(state).await
        }
    }
}

async fn serve() -> MainResult {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let bind: SocketAddr = std::env::var("SSM_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into()).parse()?;
    let state = AppState::with_config(connect(20).await?, Config::from_env()?);
    spawn_maintenance(state.clone());
    ssm_server::hub::spawn_listener(state.pool.clone(), state.hub.clone());
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
