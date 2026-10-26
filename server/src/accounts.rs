//! Account and invite creation, shared by the Admin API and `ssm-admin`.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::secrets;

pub const INVITE_TTL: Duration = Duration::days(7);

/// 3–32 characters of `[a-z0-9_.-]` (ADR-0007).
pub fn is_valid_username(name: &str) -> bool {
    (3..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
}

pub async fn create_account(conn: &mut PgConnection, username: &str, role: &str) -> sqlx::Result<Option<Uuid>> {
    let id = Uuid::new_v4();
    let inserted =
        sqlx::query("INSERT INTO accounts (id, username, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING")
            .bind(id)
            .bind(username)
            .bind(role)
            .execute(conn)
            .await?;
    Ok((inserted.rows_affected() == 1).then_some(id))
}

/// Creates a fresh invite and invalidates any older unused invite of the account.
pub async fn create_invite(conn: &mut PgConnection, account_id: Uuid) -> sqlx::Result<(String, DateTime<Utc>)> {
    sqlx::query(
        "UPDATE invites SET expires_at = now() WHERE account_id = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(account_id)
    .execute(&mut *conn)
    .await?;
    let (code, hash) = secrets::new_invite_code();
    let expires_at = Utc::now() + INVITE_TTL;
    sqlx::query("INSERT INTO invites (id, account_id, code_hash, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(hash)
        .bind(expires_at)
        .execute(conn)
        .await?;
    Ok((code, expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rules() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("bob_2.x-y"));
        assert!(!is_valid_username("al"));
        assert!(!is_valid_username("Alice"));
        assert!(!is_valid_username("a b c"));
        assert!(!is_valid_username(&"a".repeat(33)));
    }
}
