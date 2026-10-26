//! Push wake-ups to a local stand-in for a UnifiedPush distributor.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{TestEnv, b64};
use serde_json::json;
use ssm_server::Config;
use ssm_server::push::PushConfig;
use uuid::Uuid;

/// (path, body) of every received POST.
type Hits = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Receiver recording every POST; `/gone` answers 410.
async fn receiver() -> (String, Hits) {
    let hits: Hits = Arc::default();
    let recorded = hits.clone();
    let app = axum::Router::new().fallback(move |uri: axum::http::Uri, body: axum::body::Bytes| {
        let recorded = recorded.clone();
        async move {
            recorded.lock().unwrap().push((uri.path().to_owned(), body.to_vec()));
            if uri.path() == "/gone" { StatusCode::GONE } else { StatusCode::OK }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, hits)
}

fn count(hits: &Hits, path: &str) -> usize {
    hits.lock().unwrap().iter().filter(|(p, _)| p == path).count()
}

#[tokio::test]
async fn wake_ups_are_content_free_coalesced_and_skip_connected_devices() {
    let push = PushConfig {
        min_interval: Duration::from_millis(400),
        allow_private: true,
        allow_http: true,
        fcm_service_account: None,
    };
    let env = TestEnv::start_with(Config { push, ..Config::default() }).await;
    let api = &env.api;
    let (url, hits) = receiver().await;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;

    let (status, _) = api
        .call(
            Method::PUT,
            "/v1/push-endpoint",
            Some(&bob.token),
            Some(json!({ "kind": "unifiedpush", "endpoint": format!("{url}/bob") })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api
        .call(
            Method::PUT,
            "/v1/push-endpoint",
            Some(&bob.token),
            Some(json!({ "kind": "unifiedpush", "endpoint": "file:///etc/passwd" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Conversation notice + message arrive within the interval: one push now,
    // exactly one follow-up later.
    let (_, conv) = api
        .call(
            Method::POST,
            "/v1/conversations",
            Some(&alice.token),
            Some(json!({ "kind": "direct", "members": [bob.account_id] })),
        )
        .await;
    let id = conv["conversation_id"].as_str().unwrap().to_owned();
    let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(b"secret text") });
    api.call(Method::POST, &format!("/v1/conversations/{id}/messages"), Some(&alice.token), Some(body)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(count(&hits, "/bob"), 1, "first wake-up immediately");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(count(&hits, "/bob"), 2, "one follow-up for everything in the interval");
    assert!(hits.lock().unwrap().iter().all(|(_, body)| body == b"1"), "no content in pushes");

    // While Bob has an open WebSocket there is no push.
    {
        let _connected = env.state.hub.connection(bob.device_id);
        let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(b"x") });
        api.call(Method::POST, &format!("/v1/conversations/{id}/messages"), Some(&alice.token), Some(body)).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(count(&hits, "/bob"), 2);
    }

    // An endpoint answering 410 Gone is removed.
    api.call(
        Method::PUT,
        "/v1/push-endpoint",
        Some(&bob.token),
        Some(json!({ "kind": "unifiedpush", "endpoint": format!("{url}/gone") })),
    )
    .await;
    let body = json!({ "client_id": Uuid::new_v4(), "session_id": "s", "ciphertext": b64(b"y") });
    api.call(Method::POST, &format!("/v1/conversations/{id}/messages"), Some(&alice.token), Some(body)).await;
    let mut removed = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM push_endpoints").fetch_one(&env.pool).await.unwrap();
        if left == 0 {
            removed = true;
            break;
        }
    }
    assert!(removed, "410 endpoint removed");
    assert_eq!(count(&hits, "/gone"), 1);

    env.stop().await;
}
