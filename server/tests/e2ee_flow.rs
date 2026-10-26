//! Two real ssm-core crypto stores exchange a Megolm key through the server:
//! key upload, claim, to-device, event stream. Validates the wire formats.

mod common;

use axum::http::{Method, StatusCode};
use common::{ActiveTestDevice, Api, TestDevice, TestEnv, b64, key};
use serde_json::{Value, json};
use ssm_core::e2ee::{ClaimedKey, CryptoStore, Received, RecipientDevice};
use ssm_proto::B64;
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;

fn device_with_store(seed: u8, store: &CryptoStore) -> TestDevice {
    TestDevice { key: key(seed), olm_identity: store.identity_key(), olm_fingerprint: store.fingerprint_key() }
}

async fn upload_keys(api: &Api, device: &ActiveTestDevice, store: &mut CryptoStore) {
    let keys: Vec<Value> =
        store.generate_one_time_keys(5).iter().map(|(id, k)| json!({ "key_id": id, "public_key": b64(k) })).collect();
    let (fallback_id, fallback) = store.generate_fallback_key().unwrap();
    let body =
        json!({ "one_time_keys": keys, "fallback_key": { "key_id": fallback_id, "public_key": b64(&fallback) } });
    let (status, uploaded) = api.call(Method::POST, "/v1/keys/one-time", Some(&device.token), Some(body)).await;
    assert_eq!((status, uploaded["one_time_key_count"].as_u64()), (StatusCode::OK, Some(5)));
    store.mark_keys_published();
}

#[tokio::test]
async fn megolm_key_exchange_through_the_server() {
    let env = TestEnv::start().await;
    let api = &env.api;
    let admin = env.admin().await;

    let mut alice_store = CryptoStore::new();
    let mut bob_store = CryptoStore::new();
    let alice = env.activate(&admin, "alice", device_with_store(10, &alice_store)).await;
    let bob = env.activate(&admin, "bob", device_with_store(20, &bob_store)).await;
    alice_store.set_device_id(alice.device_id);
    bob_store.set_device_id(bob.device_id);
    upload_keys(api, &bob, &mut bob_store).await;

    // Alice resolves Bob's devices and claims keys for those that need one.
    let (_, found) = api.call(Method::GET, "/v1/accounts/by-username/bob", Some(&alice.token), None).await;
    let (_, devices) = api
        .call(
            Method::GET,
            &format!("/v1/accounts/{}/devices", found["account_id"].as_str().unwrap()),
            Some(&alice.token),
            None,
        )
        .await;
    let mut recipients = vec![RecipientDevice { device_id: alice.device_id, identity_key: alice_store.identity_key() }];
    for d in devices.as_array().unwrap() {
        recipients.push(RecipientDevice {
            device_id: d["device_id"].as_str().unwrap().parse().unwrap(),
            identity_key: B64::decode(d["olm_identity_key"].as_str().unwrap()).unwrap().try_into().unwrap(),
        });
    }
    let conversation = Uuid::new_v4();
    let need = alice_store.devices_needing_keys(conversation, &recipients, NOW).unwrap();
    assert_eq!(need, [bob.device_id]);
    let (_, claimed) =
        api.call(Method::POST, "/v1/keys/claim", Some(&alice.token), Some(json!({ "device_ids": need }))).await;
    let claimed: Vec<ClaimedKey> = claimed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| ClaimedKey {
            device_id: k["device_id"].as_str().unwrap().parse().unwrap(),
            one_time_key: B64::decode(k["public_key"].as_str().unwrap()).unwrap().try_into().unwrap(),
        })
        .collect();

    // Share the group session over Olm via the server.
    let share = alice_store.share_group_session(conversation, &recipients, &claimed, NOW).unwrap();
    let messages: Vec<Value> = share
        .messages
        .iter()
        .map(|m| json!({ "device_id": m.device_id, "message_type": m.message_type, "ciphertext": b64(&m.ciphertext) }))
        .collect();
    let (status, sent) =
        api.call(Method::POST, "/v1/to-device", Some(&alice.token), Some(json!({ "messages": messages }))).await;
    assert_eq!((status, sent["delivered"].as_u64()), (StatusCode::OK, Some(1)));

    // Bob processes his event stream.
    let (_, page) = api.call(Method::GET, "/v1/events", Some(&bob.token), None).await;
    let payload = &page["events"][0]["payload"];
    let received = bob_store
        .receive_to_device(
            payload["sender_device_id"].as_str().unwrap().parse().unwrap(),
            B64::decode(payload["sender_identity_key"].as_str().unwrap()).unwrap().try_into().unwrap(),
            payload["message_type"].as_u64().unwrap() as u8,
            &B64::decode(payload["ciphertext"].as_str().unwrap()).unwrap(),
            NOW,
        )
        .unwrap();
    assert_eq!(
        received,
        Received::GroupKey { conversation_id: conversation, session_id: share_session_id(&alice_store, conversation) }
    );

    // Messages encrypted by Alice decrypt on Bob's side, repeatedly.
    let sent = alice_store.encrypt(conversation, "Hallo Bob".as_bytes()).unwrap();
    for _ in 0..2 {
        let plain = bob_store.decrypt(conversation, alice.device_id, &sent.session_id, &sent.ciphertext).unwrap();
        assert_eq!(plain.as_slice(), "Hallo Bob".as_bytes());
    }

    env.stop().await;
}

fn share_session_id(store: &CryptoStore, conversation: Uuid) -> String {
    // Encrypting reveals the current outbound session id without exposing internals.
    let mut copy = CryptoStore::from_bytes(&store.to_bytes()).unwrap();
    copy.encrypt(conversation, b"").unwrap().session_id
}
