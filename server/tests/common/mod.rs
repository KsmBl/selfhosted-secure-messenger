//! Shared harness: throwaway PostgreSQL (postgresql_embedded), router calls,
//! and helpers for admins and devices. The first run downloads PostgreSQL
//! binaries into ~/.theseus.

#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use ed25519_dalek::SigningKey;
use postgresql_embedded::PostgreSQL;
use serde_json::{Value, json};
use sqlx::PgPool;
use ssm_proto::{B64, signing};
use ssm_server::{AppState, MIGRATOR, accounts, router};
use tower::ServiceExt;
use uuid::Uuid;

pub struct TestEnv {
    pub postgres: PostgreSQL,
    pub pool: PgPool,
    pub state: AppState,
    pub api: Api,
}

impl TestEnv {
    pub async fn start() -> Self {
        let mut postgres = PostgreSQL::default();
        postgres.setup().await.unwrap();
        postgres.start().await.unwrap();
        postgres.create_database("ssm_test").await.unwrap();
        let pool = PgPool::connect(&postgres.settings().url("ssm_test")).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let state = AppState::new(pool.clone());
        let api = Api { router: router(state.clone()) };
        Self { postgres, pool, state, api }
    }

    pub async fn stop(self) {
        self.pool.close().await;
        self.postgres.stop().await.unwrap();
    }

    /// Bootstraps an admin and returns a logged-in admin session.
    pub async fn admin(&self) -> Admin {
        let key = key(200);
        let key_id = bootstrap_admin(&self.pool, &key).await;
        let token = admin_login(&self.api, &key, key_id).await;
        Admin { key, key_id, token }
    }

    /// Creates an account, enrolls a device with its invite, approves it and
    /// logs it in.
    pub async fn active_device(&self, admin: &Admin, username: &str, seed: u8) -> ActiveTestDevice {
        self.activate(admin, username, TestDevice::new(seed)).await
    }

    /// Like `active_device`, with caller-provided keys (e.g. real Olm keys).
    pub async fn activate(&self, admin: &Admin, username: &str, device: TestDevice) -> ActiveTestDevice {
        let (status, invite) = self
            .api
            .call(Method::POST, "/v1/admin/accounts", Some(&admin.token), Some(json!({ "username": username })))
            .await;
        assert_eq!(status, StatusCode::OK, "{invite}");
        let (status, enrolled) = device.enroll(&self.api, Some(invite["invite_code"].as_str().unwrap()), None).await;
        assert_eq!(status, StatusCode::OK, "{enrolled}");
        let device_id: Uuid = enrolled["device_id"].as_str().unwrap().parse().unwrap();
        let (status, _) = self
            .api
            .call(Method::POST, &format!("/v1/admin/devices/{device_id}/approve"), Some(&admin.token), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, session) = device.login(&self.api, device_id).await;
        assert_eq!(status, StatusCode::OK);
        ActiveTestDevice {
            account_id: invite["account_id"].as_str().unwrap().parse().unwrap(),
            device_id,
            token: session["token"].as_str().unwrap().to_owned(),
            device,
        }
    }
}

pub struct Api {
    pub router: Router,
}

impl Api {
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
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

    pub async fn nonce(&self, path: &str, token: Option<&str>) -> Vec<u8> {
        let (status, body) = self.call(Method::POST, path, token, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        B64::decode(body["nonce"].as_str().unwrap()).unwrap()
    }
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn b64(bytes: &[u8]) -> String {
    B64::encode(bytes)
}

pub struct Admin {
    pub key: SigningKey,
    pub key_id: Uuid,
    pub token: String,
}

impl Admin {
    pub async fn confirm(&self, api: &Api, action: &str, target: &str) -> Value {
        let nonce = api.nonce("/v1/admin/confirm/challenge", Some(&self.token)).await;
        let sig = signing::sign(&self.key, &signing::admin_confirm_message(&nonce, action, target));
        json!({ "nonce": b64(&nonce), "signature": b64(&sig) })
    }
}

pub struct TestDevice {
    pub key: SigningKey,
    pub olm_identity: [u8; 32],
    pub olm_fingerprint: [u8; 32],
}

impl TestDevice {
    pub fn new(seed: u8) -> Self {
        Self { key: key(seed), olm_identity: [seed.wrapping_add(1); 32], olm_fingerprint: [seed.wrapping_add(2); 32] }
    }

    pub async fn enroll(&self, api: &Api, invite: Option<&str>, username: Option<&str>) -> (StatusCode, Value) {
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

    pub async fn login(&self, api: &Api, device_id: Uuid) -> (StatusCode, Value) {
        let nonce = api.nonce("/v1/auth/challenge", None).await;
        let sig = signing::sign(&self.key, &signing::device_auth_message(&nonce, device_id));
        let body = json!({ "device_id": device_id, "nonce": b64(&nonce), "signature": b64(&sig) });
        api.call(Method::POST, "/v1/auth/session", None, Some(body)).await
    }
}

pub struct ActiveTestDevice {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub token: String,
    pub device: TestDevice,
}

pub async fn admin_login(api: &Api, admin_key: &SigningKey, key_id: Uuid) -> String {
    let nonce = api.nonce("/v1/admin/auth/challenge", None).await;
    let sig = signing::sign(admin_key, &signing::admin_auth_message(&nonce, key_id));
    let body = json!({ "admin_key_id": key_id, "nonce": b64(&nonce), "signature": b64(&sig) });
    let (status, body) = api.call(Method::POST, "/v1/admin/auth/session", None, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"].as_str().unwrap().to_owned()
}

/// Same steps as `ssm-admin bootstrap`.
pub async fn bootstrap_admin(pool: &PgPool, admin_key: &SigningKey) -> Uuid {
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
