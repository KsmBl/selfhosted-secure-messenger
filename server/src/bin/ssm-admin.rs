//! Server-side administration CLI (ADR-0006, ADR-0007). Runs on the server
//! host with direct database access; uses `SSM_DATABASE_URL`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sqlx::PgPool;
use ssm_proto::B64;
use ssm_proto::api::DeviceAction;
use ssm_server::audit::{self, Entry};
use ssm_server::devices::ActionOutcome;
use ssm_server::{MIGRATOR, accounts};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "ssm-admin", about = "Administration CLI for ssm-server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the first admin account and register its admin public key.
    Bootstrap {
        #[arg(long)]
        username: String,
        /// Ed25519 admin public key, base64url.
        #[arg(long)]
        admin_public_key: String,
    },
    /// Register an additional admin public key for an existing admin account.
    AddAdminKey {
        #[arg(long)]
        username: String,
        #[arg(long)]
        admin_public_key: String,
    },
    /// Emergency: revoke an admin key and end its sessions.
    RevokeAdminKey {
        #[arg(long)]
        id: Uuid,
    },
    /// Create a user account and print its invite code.
    CreateAccount {
        #[arg(long)]
        username: String,
    },
    /// Emergency: revoke a device (it is deleted completely).
    RevokeDevice {
        #[arg(long)]
        id: Uuid,
    },
    /// Verify the hash chain of the admin audit log.
    VerifyAudit,
    /// DEVELOPMENT ONLY: generate an admin keypair into a file (mode 0600).
    /// Production admin keys are generated inside the client.
    DevKeygen {
        #[arg(long)]
        out: PathBuf,
    },
}

type CliResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> CliResult {
    let cli = Cli::parse();
    if let Command::DevKeygen { out } = &cli.command {
        return dev_keygen(out);
    }
    let database_url = std::env::var("SSM_DATABASE_URL").map_err(|_| "SSM_DATABASE_URL is not set")?;
    let pool = PgPool::connect(&database_url).await?;
    MIGRATOR.run(&pool).await?;

    match cli.command {
        Command::Bootstrap { username, admin_public_key } => bootstrap(&pool, &username, &admin_public_key).await,
        Command::AddAdminKey { username, admin_public_key } => add_admin_key(&pool, &username, &admin_public_key).await,
        Command::RevokeAdminKey { id } => revoke_admin_key(&pool, id).await,
        Command::CreateAccount { username } => create_account(&pool, &username).await,
        Command::RevokeDevice { id } => revoke_device(&pool, id).await,
        Command::VerifyAudit => verify_audit(&pool).await,
        Command::DevKeygen { .. } => unreachable!(),
    }
}

fn parse_public_key(text: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = B64::decode(text).ok_or("admin public key is not valid base64url")?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "admin public key must be 32 bytes")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| "not a valid Ed25519 public key")?;
    Ok(key)
}

fn cli_entry<'a>(action: &'a str, target: &'a str) -> Entry<'a> {
    Entry { admin_account_id: None, action, target, result: "ok (cli)", correlation_id: Uuid::new_v4() }
}

async fn insert_admin_key(conn: &mut sqlx::PgConnection, account_id: Uuid, key: &[u8; 32]) -> sqlx::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO admin_keys (id, account_id, public_key) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(account_id)
        .bind(key.as_slice())
        .execute(conn)
        .await?;
    Ok(id)
}

async fn bootstrap(pool: &PgPool, username: &str, public_key: &str) -> CliResult {
    let key = parse_public_key(public_key)?;
    if !accounts::is_valid_username(username) {
        return Err("username must be 3-32 characters of [a-z0-9_.-]".into());
    }
    let mut tx = pool.begin().await?;
    let admins: i64 =
        sqlx::query_scalar("SELECT count(*) FROM accounts WHERE role = 'admin'").fetch_one(&mut *tx).await?;
    if admins > 0 {
        return Err("an admin already exists; use add-admin-key or the Admin API".into());
    }
    let account_id = accounts::create_account(&mut tx, username, "admin").await?.ok_or("username is taken")?;
    let key_id = insert_admin_key(&mut tx, account_id, &key).await?;
    let (invite, expires_at) = accounts::create_invite(&mut tx, account_id).await?;
    audit::append(&mut tx, cli_entry("admin.bootstrap", &format!("account:{account_id}"))).await?;
    tx.commit().await?;
    println!("admin account: {account_id}\nadmin key id:  {key_id}");
    println!("invite code for the admin's first chat device: {invite} (expires {expires_at})");
    Ok(())
}

async fn add_admin_key(pool: &PgPool, username: &str, public_key: &str) -> CliResult {
    let key = parse_public_key(public_key)?;
    let mut tx = pool.begin().await?;
    let account_id: Uuid = sqlx::query_scalar("SELECT id FROM accounts WHERE username = $1 AND role = 'admin'")
        .bind(username)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or("no admin account with that username")?;
    let key_id = insert_admin_key(&mut tx, account_id, &key).await?;
    audit::append(&mut tx, cli_entry("admin_key.add", &format!("admin_key:{key_id}"))).await?;
    tx.commit().await?;
    println!("admin key id: {key_id}");
    Ok(())
}

async fn revoke_admin_key(pool: &PgPool, id: Uuid) -> CliResult {
    let mut tx = pool.begin().await?;
    let updated = sqlx::query("UPDATE admin_keys SET status = 'revoked' WHERE id = $1 AND status = 'active'")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if updated.rows_affected() == 0 {
        return Err("no active admin key with that id".into());
    }
    sqlx::query("DELETE FROM admin_sessions WHERE admin_key_id = $1").bind(id).execute(&mut *tx).await?;
    audit::append(&mut tx, cli_entry("admin_key.revoke", &format!("admin_key:{id}"))).await?;
    tx.commit().await?;
    println!("admin key {id} revoked");
    Ok(())
}

async fn create_account(pool: &PgPool, username: &str) -> CliResult {
    if !accounts::is_valid_username(username) {
        return Err("username must be 3-32 characters of [a-z0-9_.-]".into());
    }
    let mut tx = pool.begin().await?;
    let account_id = accounts::create_account(&mut tx, username, "user").await?.ok_or("username is taken")?;
    let (invite, expires_at) = accounts::create_invite(&mut tx, account_id).await?;
    audit::append(&mut tx, cli_entry("account.create", &format!("account:{account_id}"))).await?;
    tx.commit().await?;
    println!("account: {account_id}\ninvite code: {invite} (expires {expires_at})");
    Ok(())
}

async fn revoke_device(pool: &PgPool, id: Uuid) -> CliResult {
    let mut tx = pool.begin().await?;
    let outcome = ssm_server::devices::apply_action(&mut tx, id, DeviceAction::Revoke, None, " (cli)").await?;
    tx.commit().await?;
    match outcome {
        ActionOutcome::Changed(_) => {
            ssm_server::hub::publish(pool, &[ssm_server::hub::HubEvent::Close { device_id: id }]).await?;
            println!("device {id} revoked and deleted");
            Ok(())
        }
        ActionOutcome::NotFound => Err("no device with that id".into()),
        ActionOutcome::InvalidTransition(status) => Err(format!("cannot revoke a {} device", status.as_str()).into()),
    }
}

async fn verify_audit(pool: &PgPool) -> CliResult {
    match audit::verify_chain(pool).await? {
        Ok(count) => {
            println!("audit chain intact ({count} entries)");
            Ok(())
        }
        Err(id) => Err(format!("audit chain broken at entry {id}").into()),
    }
}

fn dev_keygen(out: &PathBuf) -> CliResult {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(out)?;
    writeln!(file, "{}", B64::encode(&secret))?;
    println!("{}", B64::encode(&key.verifying_key().to_bytes()));
    eprintln!("private key written to {} (development use only)", out.display());
    Ok(())
}
