//! Deletion journal: deletions survive a restore from an older backup.

mod common;

use axum::http::{Method, StatusCode};
use common::{TestEnv, b64};
use serde_json::json;
use ssm_server::manage::{self, Actor};
use uuid::Uuid;

#[tokio::test]
async fn replay_deletes_restored_messages_and_accounts_again() {
    let dir = std::env::temp_dir().join(format!("ssm-journal-{}", Uuid::new_v4()));
    let journal = dir.join("deletions.log");
    let config = ssm_server::Config { deletion_journal: Some(journal.clone()), ..Default::default() };
    let env = TestEnv::start_with(config).await;
    let api = &env.api;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;
    let carol = env.active_device(&admin, "carol", 30).await;

    let (_, conv) = api
        .call(
            Method::POST,
            "/v1/conversations",
            Some(&alice.token),
            Some(json!({ "kind": "group", "members": [bob.account_id, carol.account_id] })),
        )
        .await;
    let id = conv["conversation_id"].as_str().unwrap().to_owned();
    let mut sent = Vec::new();
    for text in ["keep", "delete me"] {
        let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(text.as_bytes()) });
        let (status, msg) =
            api.call(Method::POST, &format!("/v1/conversations/{id}/messages"), Some(&alice.token), Some(body)).await;
        assert_eq!(status, StatusCode::OK);
        sent.push(msg["message_id"].as_str().unwrap().parse::<Uuid>().unwrap());
    }

    // "Backup": the state before the deletions.
    let snapshot: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM messages WHERE id = $1")
        .bind(sent[1])
        .fetch_one(&env.pool)
        .await
        .unwrap();

    let (status, _) = api
        .call(
            Method::POST,
            &format!("/v1/messages/{}/delete-for-all", sent[1]),
            Some(&bob.token),
            Some(json!({ "operation_id": Uuid::new_v4() })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    manage::delete_account(&env.state, Actor::TUI, carol.account_id).await.unwrap();
    let text = std::fs::read_to_string(&journal).unwrap();
    assert!(text.contains(&format!("message {}", sent[1])) && text.contains(&format!("account {}", carol.account_id)));

    // "Restore": the message is back, the account too.
    sqlx::query("UPDATE messages SET ciphertext = $2, session_id = 's', deleted_at = NULL, deleted_by = NULL, delete_job_id = NULL WHERE id = $1")
        .bind(sent[1])
        .bind(&snapshot)
        .execute(&env.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO accounts (id, username, role, status) VALUES ($1, 'carol', 'user', 'active')")
        .bind(carol.account_id)
        .execute(&env.pool)
        .await
        .unwrap();

    let result = manage::replay_deletions(&env.state, Actor::CLI, &journal).await.unwrap();
    assert!(result.contains("1 messages and 1 accounts"), "{result}");
    let deleted: Vec<(Uuid, bool)> =
        sqlx::query_as("SELECT id, deleted_at IS NOT NULL FROM messages WHERE id = ANY($1) ORDER BY seq")
            .bind(&sent)
            .fetch_all(&env.pool)
            .await
            .unwrap();
    assert_eq!(deleted, [(sent[0], false), (sent[1], true)]);
    let carol_exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE id = $1)")
        .bind(carol.account_id)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert!(!carol_exists);

    // Idempotent.
    let again = manage::replay_deletions(&env.state, Actor::CLI, &journal).await.unwrap();
    assert!(again.contains("0 messages and 0 accounts"), "{again}");
    std::fs::remove_dir_all(dir).unwrap();
    env.stop().await;
}
