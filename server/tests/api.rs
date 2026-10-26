//! End-to-end API tests against a throwaway PostgreSQL (postgresql_embedded).
//! The first run downloads PostgreSQL binaries into ~/.theseus.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use ed25519_dalek::SigningKey;
use postgresql_embedded::PostgreSQL;
use serde_json::{Value, json};
use sqlx::PgPool;
use ssm_proto::{B64, signing};
use ssm_server::{AppState, MIGRATOR, accounts, audit, router};
use tower::ServiceExt;
use uuid::Uuid;

struct Api {
    router: Router,
}

impl Api {
    async fn call(&self, method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(path).header("content-type", "application/json");
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let body = body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty);
        let response = self.router.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn nonce(&self, path: &str, token: Option<&str>) -> Vec<u8> {
        let (status, body) = self.call(Method::POST, path, token, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        B64::decode(body["nonce"].as_str().unwrap()).unwrap()
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn b64(bytes: &[u8]) -> String {
    B64::encode(bytes)
}

struct TestDevice {
    key: SigningKey,
    olm_identity: [u8; 32],
    olm_fingerprint: [u8; 32],
}

impl TestDevice {
    fn new(seed: u8) -> Self {
        Self { key: key(seed), olm_identity: [seed.wrapping_add(1); 32], olm_fingerprint: [seed.wrapping_add(2); 32] }
    }

    async fn enroll(&self, api: &Api, invite: Option<&str>, username: Option<&str>) -> (StatusCode, Value) {
        let nonce = api.nonce("/v1/devices/enroll/challenge", None).await;
        let public = self.key.verifying_key().to_bytes();
        let msg = signing::enroll_message(&nonce, &public, &self.olm_identity, &self.olm_fingerprint);
        let body = json!({
            "invite_code": invite, "username": username, "display_name": "Test phone",
            "signing_key": b64(&public), "olm_identity_key": b64(&self.olm_identity),
            "olm_fingerprint_key": b64(&self.olm_fingerprint),
            "nonce": b64(&nonce), "signature": b64(&signing::sign(&self.key, &msg)),
        });
        api.call(Method::POST, "/v1/devices/enroll", None, Some(body)).await
    }

    async fn login(&self, api: &Api, device_id: Uuid) -> (StatusCode, Value) {
        let nonce = api.nonce("/v1/auth/challenge", None).await;
        let sig = signing::sign(&self.key, &signing::device_auth_message(&nonce, device_id));
        let body = json!({ "device_id": device_id, "nonce": b64(&nonce), "signature": b64(&sig) });
        api.call(Method::POST, "/v1/auth/session", None, Some(body)).await
    }
}

async fn admin_login(api: &Api, admin_key: &SigningKey, key_id: Uuid) -> String {
    let nonce = api.nonce("/v1/admin/auth/challenge", None).await;
    let sig = signing::sign(admin_key, &signing::admin_auth_message(&nonce, key_id));
    let body = json!({ "admin_key_id": key_id, "nonce": b64(&nonce), "signature": b64(&sig) });
    let (status, body) = api.call(Method::POST, "/v1/admin/auth/session", None, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"].as_str().unwrap().to_owned()
}

async fn confirm(api: &Api, admin_token: &str, admin_key: &SigningKey, action: &str, target: &str) -> Value {
    let nonce = api.nonce("/v1/admin/confirm/challenge", Some(admin_token)).await;
    let sig = signing::sign(admin_key, &signing::admin_confirm_message(&nonce, action, target));
    json!({ "nonce": b64(&nonce), "signature": b64(&sig) })
}

/// Same steps as `ssm-admin bootstrap`.
async fn bootstrap_admin(pool: &PgPool, admin_key: &SigningKey) -> Uuid {
    let mut tx = pool.begin().await.unwrap();
    let account = accounts::create_account(&mut tx, "root", "admin").await.unwrap().unwrap();
    let key_id = Uuid::new_v4();
    sqlx::query("INSERT INTO admin_keys (id, account_id, public_key) VALUES ($1, $2, $3)")
        .bind(key_id)
        .bind(account)
        .bind(admin_key.verifying_key().to_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    key_id
}

#[tokio::test]
async fn enrollment_approval_revocation_and_audit() {
    let mut postgres = PostgreSQL::default();
    postgres.setup().await.unwrap();
    postgres.start().await.unwrap();
    postgres.create_database("ssm_test").await.unwrap();
    let pool = PgPool::connect(&postgres.settings().url("ssm_test")).await.unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let api = Api { router: router(AppState { pool: pool.clone() }) };

    // Admin login with the bootstrap key; a wrong key is refused.
    let admin_key = key(200);
    let key_id = bootstrap_admin(&pool, &admin_key).await;
    let admin = admin_login(&api, &admin_key, key_id).await;
    let nonce = api.nonce("/v1/admin/auth/challenge", None).await;
    let forged = signing::sign(&key(201), &signing::admin_auth_message(&nonce, key_id));
    let (status, _) = api
        .call(
            Method::POST,
            "/v1/admin/auth/session",
            None,
            Some(json!({ "admin_key_id": key_id, "nonce": b64(&nonce), "signature": b64(&forged) })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Account + invite.
    let (status, invite) =
        api.call(Method::POST, "/v1/admin/accounts", Some(&admin), Some(json!({ "username": "alice" }))).await;
    assert_eq!(status, StatusCode::OK, "{invite}");
    let code = invite["invite_code"].as_str().unwrap().to_owned();
    let (status, _) =
        api.call(Method::POST, "/v1/admin/accounts", Some(&admin), Some(json!({ "username": "alice" }))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // First device enrolls with the invite (case-insensitive); the invite is single-use.
    let phone = TestDevice::new(1);
    let (status, enrolled) = phone.enroll(&api, Some(&code.to_lowercase()), None).await;
    assert_eq!(status, StatusCode::OK, "{enrolled}");
    assert_eq!(enrolled["status"], "pending");
    let phone_id: Uuid = enrolled["device_id"].as_str().unwrap().parse().unwrap();
    let (status, _) = TestDevice::new(2).enroll(&api, Some(&code), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = TestDevice::new(3).enroll(&api, None, Some("nobody")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Pending device: status only.
    let (status, session) = phone.login(&api, phone_id).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let phone_token = session["token"].as_str().unwrap().to_owned();
    let (status, body) = api.call(Method::GET, "/v1/devices/status", Some(&phone_token), None).await;
    assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("pending")));
    let (status, _) = api.call(Method::GET, "/v1/devices", Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Device tokens never work on the Admin API.
    let (status, _) = api.call(Method::GET, "/v1/admin/devices", Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Admin approves.
    let (status, pending) = api.call(Method::GET, "/v1/admin/devices?status=pending", Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pending.as_array().unwrap().len(), 1);
    assert_eq!(pending[0]["username"], "alice");
    let (status, approved) =
        api.call(Method::POST, &format!("/v1/admin/devices/{phone_id}/approve"), Some(&admin), None).await;
    assert_eq!((status, approved["status"].as_str()), (StatusCode::OK, Some("active")));
    let (status, devices) = api.call(Method::GET, "/v1/devices", Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(devices.as_array().unwrap().len(), 1);

    // A second device enrolls by username and gets rejected.
    let laptop = TestDevice::new(4);
    let (status, enrolled) = laptop.enroll(&api, None, Some("alice")).await;
    assert_eq!(status, StatusCode::OK);
    let laptop_id = enrolled["device_id"].as_str().unwrap();
    let (status, _) =
        api.call(Method::POST, &format!("/v1/admin/devices/{laptop_id}/reject"), Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = laptop.login(&api, laptop_id.parse().unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Revoke needs a confirmation signature bound to action and target.
    let revoke = format!("/v1/admin/devices/{phone_id}/revoke");
    let (status, body) = api.call(Method::POST, &revoke, Some(&admin), None).await;
    assert_eq!((status, body["type"].as_str()), (StatusCode::FORBIDDEN, Some("urn:ssm:problem:confirmation-required")));
    let wrong_target = confirm(&api, &admin, &admin_key, "revoke", "device:someone-else").await;
    let (status, _) = api.call(Method::POST, &revoke, Some(&admin), Some(wrong_target)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let good = confirm(&api, &admin, &admin_key, "revoke", &format!("device:{phone_id}")).await;
    let (status, body) = api.call(Method::POST, &revoke, Some(&admin), Some(good.clone())).await;
    assert_eq!((status, body["status"].as_str()), (StatusCode::OK, Some("revoked")));

    // Confirmation nonces are single-use.
    let (status, _) = api.call(Method::POST, &revoke, Some(&admin), Some(good)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Revocation ends existing sessions and blocks new ones; it is final.
    let (status, _) = api.call(Method::GET, "/v1/devices/status", Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = phone.login(&api, phone_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) =
        api.call(Method::POST, &format!("/v1/admin/devices/{phone_id}/approve"), Some(&admin), None).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Audit log: every action recorded, chain intact, tampering detected.
    let (status, events) = api.call(Method::GET, "/v1/admin/audit-events", Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK);
    let actions: Vec<&str> = events.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["device.approve", "device.revoke", "device.reject", "device.approve", "account.create"]);
    assert!(events[0]["result"].as_str().unwrap().starts_with("refused"));
    assert_eq!(audit::verify_chain(&pool).await.unwrap(), Ok(5));

    let update =
        sqlx::query("UPDATE admin_audit_events SET result = 'ok' WHERE action = 'device.reject'").execute(&pool).await;
    assert!(update.is_err(), "audit log must be append-only");
    sqlx::query("ALTER TABLE admin_audit_events DISABLE TRIGGER admin_audit_events_no_update_delete")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE admin_audit_events SET target = 'device:tampered' WHERE action = 'device.reject'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(audit::verify_chain(&pool).await.unwrap().is_err());

    pool.close().await;
    postgres.stop().await.unwrap();
}
