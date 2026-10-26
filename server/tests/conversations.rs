//! Conversations, pagination, delete-for-everyone, retention and membership.

mod common;

use axum::http::{Method, StatusCode};
use common::{ActiveTestDevice, Api, TestEnv, b64};
use serde_json::{Value, json};
use ssm_server::conversations;
use uuid::Uuid;

async fn create(api: &Api, who: &ActiveTestDevice, kind: &str, members: &[&ActiveTestDevice]) -> Value {
    let ids: Vec<Uuid> = members.iter().map(|m| m.account_id).collect();
    let (status, conv) = api
        .call(Method::POST, "/v1/conversations", Some(&who.token), Some(json!({ "kind": kind, "members": ids })))
        .await;
    assert_eq!(status, StatusCode::OK, "{conv}");
    conv
}

async fn send(api: &Api, who: &ActiveTestDevice, conv: &str, client_id: Uuid, text: &str) -> (StatusCode, Value) {
    let body = json!({ "client_id": client_id, "session_id": "sess", "ciphertext": b64(text.as_bytes()) });
    api.call(Method::POST, &format!("/v1/conversations/{conv}/messages"), Some(&who.token), Some(body)).await
}

async fn events(api: &Api, who: &ActiveTestDevice) -> Vec<Value> {
    let (status, page) = api.call(Method::GET, "/v1/events?limit=500", Some(&who.token), None).await;
    assert_eq!(status, StatusCode::OK);
    page["events"].as_array().unwrap().clone()
}

fn kinds(events: &[Value]) -> Vec<&str> {
    events.iter().map(|e| e["kind"].as_str().unwrap()).collect()
}

#[tokio::test]
async fn direct_chat_messages_and_pagination() {
    let env = TestEnv::start().await;
    let api = &env.api;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;
    let carol = env.active_device(&admin, "carol", 30).await;

    let conv = create(api, &alice, "direct", &[&bob]).await;
    let id = conv["conversation_id"].as_str().unwrap().to_owned();
    assert_eq!((conv["retention_days"].as_u64(), conv["last_seq"].as_i64()), (Some(90), Some(1)));
    assert_eq!(conv["members"].as_array().unwrap().len(), 2);
    // A second direct chat between the same people is the same conversation.
    let again = create(api, &bob, "direct", &[&alice]).await;
    assert_eq!(again["conversation_id"], conv["conversation_id"]);
    let (status, _) = api
        .call(Method::POST, "/v1/conversations", Some(&alice.token), Some(json!({ "kind": "direct", "members": [] })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 250 messages; a retried client_id does not create a duplicate.
    let first = Uuid::new_v4();
    let (_, sent) = send(api, &alice, &id, first, "m0").await;
    let (_, retry) = send(api, &alice, &id, first, "m0").await;
    assert_eq!(sent["message_id"], retry["message_id"]);
    assert_eq!(sent["seq"].as_i64(), Some(2));
    for i in 1..250 {
        let (status, _) = send(api, &alice, &id, Uuid::new_v4(), &format!("m{i}")).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Newest first, 100 per page, even if more is requested.
    let path = format!("/v1/conversations/{id}/messages");
    let (status, page1) = api.call(Method::GET, &format!("{path}?limit=500"), Some(&bob.token), None).await;
    assert_eq!(status, StatusCode::OK);
    let msgs = page1["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 100);
    assert_eq!((msgs[0]["seq"].as_i64(), msgs[99]["seq"].as_i64()), (Some(251), Some(152)));
    assert_eq!(msgs[0]["kind"], "encrypted");
    assert_eq!(msgs[0]["ciphertext"].as_str(), Some(b64(b"m249").as_str()));
    assert_eq!(msgs[0]["sender_device_id"].as_str(), Some(alice.device_id.to_string().as_str()));
    let before = page1["next_before"].as_i64().unwrap();
    let (_, page2) = api.call(Method::GET, &format!("{path}?before={before}"), Some(&bob.token), None).await;
    let (_, page3) =
        api.call(Method::GET, &format!("{path}?before={}", page2["next_before"]), Some(&bob.token), None).await;
    assert_eq!(page3["messages"].as_array().unwrap().len(), 51);
    assert_eq!(page3["next_before"], Value::Null);
    assert_eq!(page3["messages"][50]["kind"], "system");
    assert_eq!(page3["messages"][50]["notice"]["notice"], "conversation_created");

    // Catching up after an event: oldest first.
    let (_, newer) = api.call(Method::GET, &format!("{path}?after=249"), Some(&bob.token), None).await;
    let seqs: Vec<i64> = newer["messages"].as_array().unwrap().iter().map(|m| m["seq"].as_i64().unwrap()).collect();
    assert_eq!(seqs, [250, 251]);

    // Outsiders see nothing.
    let (status, _) = api.call(Method::GET, &path, Some(&carol.token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(api, &carol, &id, Uuid::new_v4(), "intrude").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api.call(Method::GET, &format!("/v1/conversations/{id}"), Some(&carol.token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Bob was woken for each message; the sending device was not.
    let bob_events = events(api, &bob).await;
    assert_eq!(bob_events.iter().filter(|e| e["kind"] == "message").count(), 251);
    let alice_events = events(api, &alice).await;
    assert_eq!(alice_events.iter().filter(|e| e["kind"] == "message").count(), 1, "only the creation notice");

    env.stop().await;
}

#[tokio::test]
async fn delete_for_everyone_by_any_member() {
    let env = TestEnv::start().await;
    let api = &env.api;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;
    let carol = env.active_device(&admin, "carol", 30).await;
    let dave = env.active_device(&admin, "dave", 40).await;

    let conv = create(api, &alice, "group", &[&bob, &carol]).await;
    let id = conv["conversation_id"].as_str().unwrap().to_owned();
    let (_, sent) = send(api, &bob, &id, Uuid::new_v4(), "regret").await;
    let message_id = sent["message_id"].as_str().unwrap().to_owned();
    for who in [&alice, &bob, &carol] {
        events(api, who).await;
    }

    // Carol deletes Bob's message: allowed for any member.
    let delete = format!("/v1/messages/{message_id}/delete-for-all");
    let op = Uuid::new_v4();
    let (status, job) = api.call(Method::POST, &delete, Some(&carol.token), Some(json!({ "operation_id": op }))).await;
    assert_eq!(status, StatusCode::OK, "{job}");
    assert_eq!(job["status"], "backup_purge_pending");
    assert_eq!(job["affected_messages"].as_i64(), Some(1));
    assert!(job["backup_purge_due_at"].is_string());

    // Same operation id: same job. Another member deleting again: same job.
    let (_, repeat) = api.call(Method::POST, &delete, Some(&carol.token), Some(json!({ "operation_id": op }))).await;
    assert_eq!(repeat["job_id"], job["job_id"]);
    let (_, other) =
        api.call(Method::POST, &delete, Some(&alice.token), Some(json!({ "operation_id": Uuid::new_v4() }))).await;
    assert_eq!(other["job_id"], job["job_id"]);

    // Non-members cannot delete or see the job.
    let (status, _) =
        api.call(Method::POST, &delete, Some(&dave.token), Some(json!({ "operation_id": Uuid::new_v4() }))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let job_path = format!("/v1/delete-jobs/{}", job["job_id"].as_str().unwrap());
    let (status, _) = api.call(Method::GET, &job_path, Some(&dave.token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, seen) = api.call(Method::GET, &job_path, Some(&alice.token), None).await;
    assert_eq!((status, &seen["status"]), (StatusCode::OK, &json!("backup_purge_pending")));

    // Content is gone on the server; a tombstone remains in the timeline.
    let stored: Option<Vec<u8>> = sqlx::query_scalar("SELECT ciphertext FROM messages WHERE id = $1::uuid")
        .bind(&message_id)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert!(stored.is_none());
    let (_, page) = api.call(Method::GET, &format!("/v1/conversations/{id}/messages"), Some(&alice.token), None).await;
    let tombstone = &page["messages"][0];
    assert_eq!(tombstone["kind"], "deleted");
    assert_eq!(tombstone["deleted_by"].as_str(), Some(carol.account_id.to_string().as_str()));
    assert!(tombstone.get("ciphertext").is_none());

    // Every member device is told to drop the message.
    for who in [&alice, &bob, &carol] {
        let got = events(api, who).await;
        let deleted: Vec<&Value> = got.iter().filter(|e| e["kind"] == "message_deleted").collect();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0]["payload"]["message_id"].as_str(), Some(message_id.as_str()));
    }

    // System notices are not deletable; there is no delete-for-me endpoint.
    let notice_id = page["messages"][1]["message_id"].as_str().unwrap().to_owned();
    let (status, _) = api
        .call(
            Method::POST,
            &format!("/v1/messages/{notice_id}/delete-for-all"),
            Some(&alice.token),
            Some(json!({ "operation_id": Uuid::new_v4() })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    for path in [format!("/v1/messages/{message_id}/delete"), format!("/v1/messages/{message_id}/delete-for-me")] {
        let (status, _) = api.call(Method::POST, &path, Some(&alice.token), Some(json!({}))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }

    // Backup status only completes after the backup window.
    conversations::run_expiry(&env.pool).await.unwrap();
    let (_, still) = api.call(Method::GET, &job_path, Some(&carol.token), None).await;
    assert_eq!(still["status"], "backup_purge_pending");
    sqlx::query("UPDATE delete_jobs SET backup_purge_due_at = now() - interval '1 second'")
        .execute(&env.pool)
        .await
        .unwrap();
    conversations::run_expiry(&env.pool).await.unwrap();
    let (_, done) = api.call(Method::GET, &job_path, Some(&carol.token), None).await;
    assert_eq!(done["status"], "backup_purge_done");

    env.stop().await;
}

#[tokio::test]
async fn retention_and_membership() {
    let env = TestEnv::start().await;
    let api = &env.api;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;
    let carol = env.active_device(&admin, "carol", 30).await;
    let dave = env.active_device(&admin, "dave", 40).await;

    let conv = create(api, &alice, "group", &[&bob, &carol]).await;
    let id = conv["conversation_id"].as_str().unwrap().to_owned();
    let retention = format!("/v1/conversations/{id}/retention");
    for days in [0, 366] {
        let (status, _) = api.call(Method::PUT, &retention, Some(&bob.token), Some(json!({ "days": days }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (_, old) = send(api, &alice, &id, Uuid::new_v4(), "old").await;

    // Any member changes retention; everybody sees the notice.
    let (status, updated) = api.call(Method::PUT, &retention, Some(&bob.token), Some(json!({ "days": 7 }))).await;
    assert_eq!((status, updated["retention_days"].as_u64()), (StatusCode::OK, Some(7)));
    for who in [&alice, &bob, &carol] {
        let (_, page) =
            api.call(Method::GET, &format!("/v1/conversations/{id}/messages"), Some(&who.token), None).await;
        let notice = &page["messages"][0]["notice"];
        assert_eq!(notice["notice"], "retention_changed");
        assert_eq!((notice["from_days"].as_u64(), notice["to_days"].as_u64()), (Some(90), Some(7)));
        assert_eq!(notice["by"].as_str(), Some(bob.account_id.to_string().as_str()));
        assert!(kinds(&events(api, who).await).contains(&"conversation_updated"));
    }
    let lifetime_days: i32 =
        sqlx::query_scalar("SELECT extract(day FROM expires_at - created_at)::int FROM messages WHERE id = $1::uuid")
            .bind(old["message_id"].as_str().unwrap())
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(lifetime_days, 7, "existing messages get the new expiry");

    // Expired messages disappear from the API and the database.
    sqlx::query("UPDATE messages SET created_at = now() - interval '8 days', expires_at = now() - interval '1 day' WHERE id = $1::uuid")
        .bind(old["message_id"].as_str().unwrap())
        .execute(&env.pool)
        .await
        .unwrap();
    let (_, page) = api.call(Method::GET, &format!("/v1/conversations/{id}/messages"), Some(&carol.token), None).await;
    assert!(page["messages"].as_array().unwrap().iter().all(|m| m["message_id"] != old["message_id"]));
    conversations::run_expiry(&env.pool).await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM messages WHERE id = $1::uuid")
        .bind(old["message_id"].as_str().unwrap())
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);

    // Only the group admin (the creator) invites; a new member only sees
    // what happened after joining.
    let members = format!("/v1/conversations/{id}/members");
    send(api, &alice, &id, Uuid::new_v4(), "before dave").await;
    let invite_dave = json!({ "account_id": dave.account_id });
    let (status, body) = api.call(Method::POST, &members, Some(&bob.token), Some(invite_dave.clone())).await;
    assert_eq!((status, body["type"].as_str()), (StatusCode::FORBIDDEN, Some("urn:ssm:problem:only-admin-can-invite")));
    let (status, _) = api.call(Method::POST, &members, Some(&alice.token), Some(invite_dave.clone())).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api.call(Method::POST, &members, Some(&alice.token), Some(invite_dave)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    send(api, &alice, &id, Uuid::new_v4(), "after dave").await;
    let (_, page) = api.call(Method::GET, &format!("/v1/conversations/{id}/messages"), Some(&dave.token), None).await;
    let visible: Vec<&str> = page["messages"].as_array().unwrap().iter().map(|m| m["kind"].as_str().unwrap()).collect();
    assert_eq!(visible, ["encrypted", "system"], "own join notice and the later message only");

    // Only the admin removes others; anyone can leave.
    let (status, _) =
        api.call(Method::DELETE, &format!("{members}/{}", carol.account_id), Some(&bob.token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) =
        api.call(Method::DELETE, &format!("{members}/{}", carol.account_id), Some(&carol.token), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) =
        api.call(Method::GET, &format!("/v1/conversations/{id}/messages"), Some(&carol.token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) =
        api.call(Method::DELETE, &format!("{members}/{}", dave.account_id), Some(&alice.token), None).await;
    assert_eq!(status, StatusCode::OK);

    // The admin leaves: the longest-standing member (bob) takes over and may invite.
    let (status, info) =
        api.call(Method::DELETE, &format!("{members}/{}", alice.account_id), Some(&alice.token), None).await;
    assert_eq!(status, StatusCode::OK);
    let roles: Vec<(&str, &str, &str)> = info["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (m["username"].as_str().unwrap(), m["status"].as_str().unwrap(), m["role"].as_str().unwrap()))
        .collect();
    assert_eq!(
        roles,
        [
            ("alice", "left", "member"),
            ("bob", "active", "admin"),
            ("carol", "left", "member"),
            ("dave", "removed", "member")
        ]
    );
    let (_, page) = api.call(Method::GET, &format!("/v1/conversations/{id}/messages"), Some(&bob.token), None).await;
    assert_eq!(page["messages"][0]["notice"]["notice"], "admin_changed");
    assert_eq!(page["messages"][0]["notice"]["account_id"].as_str(), Some(bob.account_id.to_string().as_str()));
    let (status, _) =
        api.call(Method::POST, &members, Some(&bob.token), Some(json!({ "account_id": carol.account_id }))).await;
    assert_eq!(status, StatusCode::OK);

    env.stop().await;
}
