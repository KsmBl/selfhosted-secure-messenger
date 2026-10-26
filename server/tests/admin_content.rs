//! Admin mass deletion of one person's content and the notification hint.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{ActiveTestDevice, Api, TestEnv, b64};
use serde_json::{Value, json};
use uuid::Uuid;

async fn send(api: &Api, who: &ActiveTestDevice, conv: &str, text: &str) -> String {
    let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(text.as_bytes()) });
    let (status, sent) =
        api.call(Method::POST, &format!("/v1/conversations/{conv}/messages"), Some(&who.token), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    sent["message_id"].as_str().unwrap().to_owned()
}

async fn create(api: &Api, who: &ActiveTestDevice, kind: &str, members: &[Uuid]) -> String {
    let body = json!({ "kind": kind, "members": members });
    let (status, conv) = api.call(Method::POST, "/v1/conversations", Some(&who.token), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{conv}");
    conv["conversation_id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn mass_deletion_of_one_persons_messages() {
    let env = TestEnv::start().await;
    let api = &env.api;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;
    let carol = env.active_device(&admin, "carol", 30).await;

    let group = create(api, &alice, "group", &[bob.account_id, carol.account_id]).await;
    let direct = create(api, &alice, "direct", &[bob.account_id]).await;
    for i in 0..3 {
        send(api, &bob, &group, &format!("g{i}")).await;
    }
    for i in 0..2 {
        send(api, &bob, &direct, &format!("d{i}")).await;
    }
    let alice_msg = send(api, &alice, &group, "mine").await;

    // Notification hint: count and only the initial of the latest sender.
    let (status, hint) = api.call(Method::GET, "/v1/notifications/hint", Some(&carol.token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hint["sender_initial"], "A");
    assert!(hint["pending_messages"].as_i64().unwrap() >= 4);
    let (_, hint) = api.call(Method::GET, "/v1/notifications/hint", Some(&alice.token), None).await;
    assert_eq!(hint["sender_initial"], "B");

    // Scope shown before confirming.
    let summary_path = format!("/v1/admin/accounts/{}/content-summary", bob.account_id);
    let (status, summary) = api.call(Method::GET, &summary_path, Some(&admin.token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (summary["username"].as_str(), summary["messages"].as_i64(), summary["conversations"].as_i64()),
        (Some("bob"), Some(5), Some(2))
    );
    let (status, _) = api.call(Method::GET, &summary_path, Some(&alice.token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Confirmation must be bound to this action and target.
    let path = format!("/v1/admin/accounts/{}/delete-all-content", bob.account_id);
    let op = Uuid::new_v4();
    let wrong = admin.confirm(api, "delete-all-content", &format!("account:{}", alice.account_id)).await;
    let body = json!({ "operation_id": op, "nonce": wrong["nonce"], "signature": wrong["signature"] });
    let (status, _) = api.call(Method::POST, &path, Some(&admin.token), Some(body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let confirm = admin.confirm(api, "delete-all-content", &format!("account:{}", bob.account_id)).await;
    let body = json!({ "operation_id": op, "nonce": confirm["nonce"], "signature": confirm["signature"] });
    let (status, job) = api.call(Method::POST, &path, Some(&admin.token), Some(body.clone())).await;
    assert_eq!(status, StatusCode::OK, "{job}");
    let (_, again) = api.call(Method::POST, &path, Some(&admin.token), Some(body)).await;
    assert_eq!(again["job_id"], job["job_id"], "idempotent per operation id");

    // Asynchronous: poll until active data is removed.
    let job_path = format!("/v1/admin/delete-jobs/{}", job["job_id"].as_str().unwrap());
    let mut status_now = Value::Null;
    for _ in 0..50 {
        let (_, current) = api.call(Method::GET, &job_path, Some(&admin.token), None).await;
        if current["status"] == "backup_purge_pending" {
            assert_eq!(current["affected_messages"].as_i64(), Some(5));
            status_now = current["status"].clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status_now, "backup_purge_pending");

    // Bob's messages are tombstones everywhere; Alice's message is untouched.
    let (_, page) =
        api.call(Method::GET, &format!("/v1/conversations/{group}/messages"), Some(&carol.token), None).await;
    let kinds: Vec<(&str, &str)> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["kind"] != "system")
        .map(|m| (m["message_id"].as_str().unwrap(), m["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds.len(), 4);
    for (id, kind) in kinds {
        assert_eq!(kind, if id == alice_msg { "encrypted" } else { "deleted" });
    }
    let (_, summary) = api.call(Method::GET, &summary_path, Some(&admin.token), None).await;
    assert_eq!(summary["messages"].as_i64(), Some(0));

    // Start and finish are audited under the job id as correlation id.
    let (_, audit) = api.call(Method::GET, "/v1/admin/audit-events", Some(&admin.token), None).await;
    let entries: Vec<&Value> =
        audit.as_array().unwrap().iter().filter(|e| e["correlation_id"] == job["job_id"]).collect();
    let actions: Vec<&str> = entries.iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["account.delete_all_content.finished", "account.delete_all_content"]);
    assert_eq!(entries[0]["result"], "ok: 5 messages deleted");

    env.stop().await;
}
