//! Olm key distribution, to-device messages, the event stream and the WebSocket.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{TestEnv, b64};
use futures_util::StreamExt;
use serde_json::{Value, json};
use ssm_proto::api::WsMessage;
use ssm_server::router;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{self, Message};
use uuid::Uuid;

fn otks(range: std::ops::Range<u8>) -> Value {
    range.map(|i| json!({ "key_id": format!("k{i:03}"), "public_key": b64(&[i; 32]) })).collect()
}

#[tokio::test]
async fn one_time_keys_to_device_and_events() {
    let env = TestEnv::start().await;
    let api = &env.api;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;

    // Upload: 3 one-time keys + fallback; the per-device limit of 100 holds.
    let body = json!({ "one_time_keys": otks(0..3), "fallback_key": { "key_id": "fb", "public_key": b64(&[99; 32]) } });
    let (status, uploaded) = api.call(Method::POST, "/v1/keys/one-time", Some(&alice.token), Some(body)).await;
    assert_eq!((status, uploaded["one_time_key_count"].as_u64()), (StatusCode::OK, Some(3)));
    let body = json!({ "one_time_keys": otks(3..101) });
    let (status, _) = api.call(Method::POST, "/v1/keys/one-time", Some(&alice.token), Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let bad = json!({ "one_time_keys": [{ "key_id": "x", "public_key": b64(&[1; 31]) }] });
    let (status, _) = api.call(Method::POST, "/v1/keys/one-time", Some(&alice.token), Some(bad)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Claim: each one-time key exactly once, then the fallback key.
    let unknown = Uuid::new_v4();
    let mut claimed = Vec::new();
    for _ in 0..4 {
        let body = json!({ "device_ids": [alice.device_id, unknown] });
        let (status, result) = api.call(Method::POST, "/v1/keys/claim", Some(&bob.token), Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["unavailable"], json!([unknown]));
        claimed.push((result["keys"][0]["key_id"].as_str().unwrap().to_owned(), result["keys"][0]["fallback"].clone()));
    }
    let ids: Vec<&str> = claimed.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["k000", "k001", "k002", "fb"]);
    assert_eq!(claimed[3].1, json!(true));

    // Lookup and device list.
    let (status, found) = api.call(Method::GET, "/v1/accounts/by-username/alice", Some(&bob.token), None).await;
    assert_eq!((status, found["account_id"].as_str()), (StatusCode::OK, Some(alice.account_id.to_string().as_str())));
    let (status, _) = api.call(Method::GET, "/v1/accounts/by-username/mallory", Some(&bob.token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, devices) =
        api.call(Method::GET, &format!("/v1/accounts/{}/devices", alice.account_id), Some(&bob.token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(devices[0]["device_id"].as_str(), Some(alice.device_id.to_string().as_str()));
    assert_eq!(devices[0]["olm_identity_key"].as_str(), Some(b64(&alice.device.olm_identity).as_str()));

    // To-device: the server attaches the sender's identity key; unknown targets are skipped.
    let body = json!({ "messages": [
        { "device_id": alice.device_id, "message_type": 0, "ciphertext": b64(b"olm-prekey-message") },
        { "device_id": unknown, "message_type": 1, "ciphertext": b64(b"x") },
    ]});
    let (status, sent) = api.call(Method::POST, "/v1/to-device", Some(&bob.token), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!((sent["delivered"].as_u64(), &sent["skipped"]), (Some(1), &json!([unknown])));
    let bad = json!({ "messages": [{ "device_id": alice.device_id, "message_type": 7, "ciphertext": b64(b"x") }] });
    let (status, _) = api.call(Method::POST, "/v1/to-device", Some(&bob.token), Some(bad)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Events: delivered in order and deleted once acknowledged with `since`.
    let (status, page) = api.call(Method::GET, "/v1/events", Some(&alice.token), None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["events"].as_array().unwrap().len(), 1);
    let event = &page["events"][0];
    assert_eq!(event["kind"], "to_device");
    assert_eq!(event["payload"]["sender_device_id"].as_str(), Some(bob.device_id.to_string().as_str()));
    assert_eq!(event["payload"]["sender_identity_key"].as_str(), Some(b64(&bob.device.olm_identity).as_str()));
    assert_eq!(event["payload"]["ciphertext"].as_str(), Some(b64(b"olm-prekey-message").as_str()));
    assert_eq!((page["next_since"].as_i64(), page["more"].as_bool()), (Some(1), Some(false)));
    let (_, page) = api.call(Method::GET, "/v1/events?since=1", Some(&alice.token), None).await;
    assert_eq!(page["events"], json!([]));
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM events").fetch_one(&env.pool).await.unwrap();
    assert_eq!(stored, 0);

    // Bob's own stream is empty: events are strictly per device.
    let (_, page) = api.call(Method::GET, "/v1/events", Some(&bob.token), None).await;
    assert_eq!(page["events"], json!([]));

    env.stop().await;
}

async fn next_json(ws: &mut (impl StreamExt<Item = tungstenite::Result<Message>> + Unpin)) -> WsMessage {
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("timed out").unwrap().unwrap() {
        Message::Text(text) => serde_json::from_str(&text).unwrap(),
        other => panic!("unexpected frame: {other:?}"),
    }
}

#[tokio::test]
async fn websocket_wakes_up_and_closes_on_disable() {
    let env = TestEnv::start().await;
    let admin = env.admin().await;
    let alice = env.active_device(&admin, "alice", 10).await;
    let bob = env.active_device(&admin, "bob", 20).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(env.state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Without a token the upgrade is refused.
    let err = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws")).await.unwrap_err();
    assert!(matches!(err, tungstenite::Error::Http(ref r) if r.status() == StatusCode::UNAUTHORIZED));

    let mut request = format!("ws://{addr}/v1/ws").into_client_request().unwrap();
    request.headers_mut().insert("authorization", format!("Bearer {}", alice.token).parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(next_json(&mut ws).await, WsMessage::Sync { seq: 0 });

    // A to-device message for Alice produces a sync hint with the new sequence.
    let body = json!({ "messages": [{ "device_id": alice.device_id, "message_type": 1, "ciphertext": b64(b"c") }] });
    let (status, _) = env.api.call(Method::POST, "/v1/to-device", Some(&bob.token), Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next_json(&mut ws).await, WsMessage::Sync { seq: 1 });

    // Disabling the device closes the socket with 4003.
    let path = format!("/v1/admin/devices/{}/disable", alice.device_id);
    let (status, _) = env.api.call(Method::POST, &path, Some(&admin.token), None).await;
    assert_eq!(status, StatusCode::OK);
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap() {
        Message::Close(Some(frame)) => assert_eq!(frame.code, CloseCode::from(4003)),
        other => panic!("expected close frame, got {other:?}"),
    }

    env.stop().await;
}
