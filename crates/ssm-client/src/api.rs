//! Typed HTTP access to the server with automatic device sessions.
//!
//! Sessions are short-lived (15 min); the client signs a fresh challenge with
//! the device signing key whenever the token is missing, about to expire or
//! rejected.

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use ssm_proto::api::{ChallengeResponse, Problem, SessionRequest, SessionResponse};
use ssm_proto::{B64, signing};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::{ClientError, ClientResult};

/// Renew the token this long before it expires.
const RENEW_MARGIN: Duration = Duration::from_secs(60);

struct Session {
    token: String,
    valid_until: Instant,
}

pub struct Api {
    http: reqwest::Client,
    base_url: String,
    device_id: Option<Uuid>,
    signing_key: SigningKey,
    session: Mutex<Option<Session>>,
}

impl Api {
    pub fn new(base_url: &str, signing_key: SigningKey, device_id: Option<Uuid>) -> ClientResult<Self> {
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            device_id,
            signing_key,
            session: Mutex::new(None),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn set_device_id(&mut self, device_id: Uuid) {
        self.device_id = Some(device_id);
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    async fn error(response: reqwest::Response) -> ClientError {
        let status = response.status().as_u16();
        match response.json::<Problem>().await {
            Ok(problem) => ClientError::Api {
                status,
                kind: problem.kind.rsplit(':').next().unwrap_or_default().to_owned(),
                detail: problem.detail,
            },
            Err(_) => ClientError::Api { status, kind: "unknown".into(), detail: None },
        }
    }

    async fn send_raw<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> ClientResult<reqwest::Response> {
        let mut request = self.http.request(method, format!("{}{path}", self.base_url));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        Ok(request.send().await?)
    }

    /// Unauthenticated request.
    pub async fn public<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> ClientResult<T> {
        let response = self.send_raw(method, path, None, body).await?;
        if !response.status().is_success() {
            return Err(Self::error(response).await);
        }
        Ok(response.json().await?)
    }

    async fn login(&self) -> ClientResult<Session> {
        let device_id = self.device_id.ok_or_else(|| ClientError::Protocol("device is not enrolled".into()))?;
        let challenge: ChallengeResponse = self.public(Method::POST, "/v1/auth/challenge", None::<&()>).await?;
        let signature = signing::sign(&self.signing_key, &signing::device_auth_message(&challenge.nonce.0, device_id));
        let request = SessionRequest { device_id, nonce: challenge.nonce, signature: B64(signature.to_vec()) };
        let session: SessionResponse = self.public(Method::POST, "/v1/auth/session", Some(&request)).await?;
        Ok(Session { token: session.token, valid_until: Instant::now() + Duration::from_secs(session.expires_in_secs) })
    }

    /// A currently valid token, logging in when needed.
    pub async fn token(&self) -> ClientResult<String> {
        let mut session = self.session.lock().await;
        if session.as_ref().is_none_or(|s| s.valid_until.saturating_duration_since(Instant::now()) < RENEW_MARGIN) {
            *session = Some(self.login().await?);
        }
        Ok(session.as_ref().expect("session set").token.clone())
    }

    pub async fn forget_session(&self) {
        *self.session.lock().await = None;
    }

    /// Authenticated request; retries once with a new session on 401.
    pub async fn call<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> ClientResult<T> {
        for attempt in 0..2 {
            let token = self.token().await?;
            let response = self.send_raw(method.clone(), path, Some(&token), body).await?;
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.forget_session().await;
                continue;
            }
            if !response.status().is_success() {
                return Err(Self::error(response).await);
            }
            return Ok(response.json().await?);
        }
        unreachable!("loop returns on the second attempt")
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> ClientResult<T> {
        self.call(Method::GET, path, None::<&()>).await
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(&self, path: &str, body: &B) -> ClientResult<T> {
        self.call(Method::POST, path, Some(body)).await
    }

    pub async fn put<B: Serialize + ?Sized, T: DeserializeOwned>(&self, path: &str, body: &B) -> ClientResult<T> {
        self.call(Method::PUT, path, Some(body)).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> ClientResult<T> {
        self.call(Method::DELETE, path, None::<&()>).await
    }

    /// WebSocket URL (`ws://` / `wss://`) for the wake-up channel.
    pub fn websocket_url(&self) -> String {
        let url = &self.base_url;
        if let Some(rest) = url.strip_prefix("https://") {
            format!("wss://{rest}/v1/ws")
        } else if let Some(rest) = url.strip_prefix("http://") {
            format!("ws://{rest}/v1/ws")
        } else {
            format!("{url}/v1/ws")
        }
    }
}
