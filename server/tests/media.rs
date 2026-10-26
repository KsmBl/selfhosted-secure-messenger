//! Encrypted media objects: upload, linking, access rules, deletion.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{ActiveTestDevice, Api, TestEnv, b64};
use serde_json::{Value, json};
use ssm_server::Config;
use tower::ServiceExt;
use uuid::Uuid;

async fn upload(api: &Api, who: &ActiveTestDevice, conv: &str, bytes: &[u8]) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/conversations/{conv}/media"))
        .header("authorization", format!("Bearer {}", who.token))
        .header("content-type", "application/octet-stream")
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    let response = api.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn download(api: &Api, who: &ActiveTestDevice, media: &str) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .uri(format!("/v1/media/{media}"))
        .header("authorization", format!("Bearer {}", who.token))
        .body(Body::empty())
        .unwrap();
    let response = api.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    (status, axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec())
}

#[tokio::test]
async fn media_access_and_deletion() {
    let media_dir = tempfile::tempdir().unwrap();
    let config = Config { media_dir: media_dir.path().to_owned(), max_media_bytes: 1024, ..Config::default() };
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
            Some(json!({ "kind": "group", "members": [bob.account_id] })),
        )
        .await;
    let id = conv["conversation_id"].as_str().unwrap().to_owned();

    // Upload limits and membership.
    let (status, _) = upload(api, &alice, &id, &[7u8; 2000]).await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = upload(api, &carol, &id, b"x").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-members cannot upload");
    let (status, uploaded) = upload(api, &alice, &id, b"encrypted-bytes").await;
    assert_eq!(status, StatusCode::OK);
    let media = uploaded["media_id"].as_str().unwrap().to_owned();

    // Before sending, only the uploader can read it.
    assert_eq!(download(api, &bob, &media).await.0, StatusCode::NOT_FOUND);
    assert_eq!(download(api, &alice, &media).await, (StatusCode::OK, b"encrypted-bytes".to_vec()));

    // Linking: unknown or foreign ids are refused.
    let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(b"m"), "media_ids": [Uuid::new_v4()] });
    let (status, _) =
        api.call(Method::POST, &format!("/v1/conversations/{id}/messages"), Some(&alice.token), Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(b"m"), "media_ids": [media] });
    let (status, sent) =
        api.call(Method::POST, &format!("/v1/conversations/{id}/messages"), Some(&alice.token), Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(download(api, &bob, &media).await, (StatusCode::OK, b"encrypted-bytes".to_vec()));
    assert_eq!(download(api, &carol, &media).await.0, StatusCode::NOT_FOUND, "outsiders get nothing");

    // Joining later does not open earlier media.
    api.call(
        Method::POST,
        &format!("/v1/conversations/{id}/members"),
        Some(&alice.token),
        Some(json!({ "account_id": carol.account_id })),
    )
    .await;
    assert_eq!(download(api, &carol, &media).await.0, StatusCode::NOT_FOUND);

    // Delete for everyone: 410 and the file disappears.
    let message = sent["message_id"].as_str().unwrap();
    api.call(
        Method::POST,
        &format!("/v1/messages/{message}/delete-for-all"),
        Some(&bob.token),
        Some(json!({ "operation_id": Uuid::new_v4() })),
    )
    .await;
    let status = download(api, &bob, &media).await.0;
    assert!(status == StatusCode::GONE || status == StatusCode::NOT_FOUND, "{status}");
    let mut gone = false;
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if !media_dir.path().join(&media).exists() {
            gone = true;
            break;
        }
    }
    assert!(gone, "file removed from disk");
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM media_objects").fetch_one(&env.pool).await.unwrap();
    assert_eq!(rows, 0);

    env.stop().await;
}
