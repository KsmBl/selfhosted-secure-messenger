//! Push wake-ups (ADR-0008, FR-015).
//!
//! When a device gets a new event and has no open WebSocket, the server sends
//! a content-free wake-up to its push endpoint: UnifiedPush (an HTTPS URL of
//! the user's distributor, e.g. ntfy) or, as fallback, Firebase Cloud
//! Messaging. The device then fetches what it may show (`/v1/notifications/hint`).
//!
//! - At most one push per device per `min_interval`; anything arriving in
//!   between is covered by one follow-up push when the interval has passed.
//! - UnifiedPush endpoints must be HTTPS and resolve to public addresses
//!   unless allowed otherwise (protects the server's internal network).
//! - Endpoints answering 404/410 are dropped (the app unregistered).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

/// Body of every wake-up. Deliberately meaningless.
const WAKE_BODY: &[u8] = b"1";
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

#[derive(Debug, Clone)]
pub struct PushConfig {
    pub min_interval: Duration,
    /// Allow endpoints on private/loopback addresses (self-hosted ntfy in the LAN).
    pub allow_private: bool,
    /// Allow plain http:// endpoints (only sensible together with allow_private).
    pub allow_http: bool,
    /// Path of a Firebase service account JSON; FCM is off without it.
    pub fcm_service_account: Option<std::path::PathBuf>,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(10),
            allow_private: false,
            allow_http: false,
            fcm_service_account: None,
        }
    }
}

/// Why an endpoint is refused at registration or send time.
pub fn check_endpoint_url(url: &str, config: &PushConfig) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "not a valid URL".to_owned())?;
    match parsed.scheme() {
        "https" => {}
        "http" if config.allow_http => {}
        _ => return Err("the push endpoint must use https".into()),
    }
    if parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("invalid push endpoint host".into());
    }
    Ok(parsed)
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) // 100.64/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xfe00) == 0xfc00 // unique local
                || (first & 0xffc0) == 0xfe80) // link local
        }
    }
}

/// Resolves the host and refuses internal addresses unless allowed.
async fn check_destination(url: &reqwest::Url, config: &PushConfig) -> Result<(), String> {
    if config.allow_private {
        return Ok(());
    }
    let host = url.host_str().ok_or("no host")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses: Vec<_> = tokio::net::lookup_host((host, port)).await.map_err(|e| e.to_string())?.collect();
    if addresses.is_empty() || addresses.iter().any(|a| !is_public(a.ip())) {
        return Err(format!("{host} resolves to an internal address"));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

struct FcmToken {
    value: String,
    valid_until: Instant,
}

struct Fcm {
    account: ServiceAccount,
    key: jsonwebtoken::EncodingKey,
    token: Mutex<Option<FcmToken>>,
}

impl Fcm {
    fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let account: ServiceAccount = serde_json::from_str(&text).map_err(|e| format!("service account: {e}"))?;
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .map_err(|e| format!("service account key: {e}"))?;
        Ok(Self { account, key, token: Mutex::new(None) })
    }

    /// OAuth2 access token via a signed JWT (service account flow).
    async fn access_token(&self, http: &reqwest::Client) -> Result<String, String> {
        let mut token = self.token.lock().await;
        if let Some(t) = token.as_ref().filter(|t| t.valid_until > Instant::now() + Duration::from_secs(60)) {
            return Ok(t.value.clone());
        }
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": self.account.client_email, "scope": FCM_SCOPE, "aud": self.account.token_uri,
            "iat": now, "exp": now + 3600,
        });
        let jwt = jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256), &claims, &self.key)
            .map_err(|e| e.to_string())?;
        let body = format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={jwt}");
        let response: serde_json::Value = http
            .post(&self.account.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        let value = response["access_token"].as_str().ok_or("no access token in response")?.to_owned();
        let lifetime = response["expires_in"].as_u64().unwrap_or(3600);
        *token = Some(FcmToken { value: value.clone(), valid_until: Instant::now() + Duration::from_secs(lifetime) });
        Ok(value)
    }

    async fn send(&self, http: &reqwest::Client, registration_token: &str) -> Result<reqwest::StatusCode, String> {
        let access = self.access_token(http).await?;
        let url = format!("https://fcm.googleapis.com/v1/projects/{}/messages:send", self.account.project_id);
        let message = serde_json::json!({ "message": {
            "token": registration_token,
            "data": { "w": "1" },
            "android": { "priority": "HIGH" },
        }});
        let response = http.post(url).bearer_auth(access).json(&message).send().await.map_err(|e| e.to_string())?;
        Ok(response.status())
    }
}

struct Sender {
    pool: PgPool,
    config: PushConfig,
    http: reqwest::Client,
    fcm: Option<Fcm>,
}

impl Sender {
    async fn send(&self, device_id: Uuid) {
        let row: Option<(String, String)> =
            match sqlx::query_as("SELECT kind, endpoint FROM push_endpoints WHERE device_id = $1")
                .bind(device_id)
                .fetch_optional(&self.pool)
                .await
            {
                Ok(row) => row,
                Err(err) => {
                    tracing::warn!(error = %err, "push endpoint lookup failed");
                    return;
                }
            };
        let Some((kind, endpoint)) = row else { return };
        let status = match kind.as_str() {
            "unifiedpush" => {
                let url = match check_endpoint_url(&endpoint, &self.config) {
                    Ok(url) => url,
                    Err(err) => {
                        tracing::warn!(%device_id, %err, "refusing push endpoint");
                        return;
                    }
                };
                if let Err(err) = check_destination(&url, &self.config).await {
                    tracing::warn!(%device_id, %err, "refusing push endpoint");
                    return;
                }
                match self
                    .http
                    .post(url)
                    .header("content-type", "application/octet-stream")
                    .header("ttl", "86400")
                    .body(WAKE_BODY)
                    .send()
                    .await
                {
                    Ok(response) => response.status(),
                    Err(err) => {
                        tracing::info!(%device_id, error = %err, "push delivery failed");
                        return;
                    }
                }
            }
            "fcm" => {
                let Some(fcm) = &self.fcm else { return };
                match fcm.send(&self.http, &endpoint).await {
                    Ok(status) => status,
                    Err(err) => {
                        tracing::info!(%device_id, error = %err, "FCM delivery failed");
                        return;
                    }
                }
            }
            _ => return,
        };
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
            let _ = sqlx::query("DELETE FROM push_endpoints WHERE device_id = $1")
                .bind(device_id)
                .execute(&self.pool)
                .await;
            tracing::info!(%device_id, "push endpoint gone, removed");
        }
    }
}

/// Handle to queue wake-ups.
#[derive(Clone)]
pub struct Pusher {
    tx: mpsc::UnboundedSender<Uuid>,
}

impl Pusher {
    pub fn wake(&self, device_id: Uuid) {
        let _ = self.tx.send(device_id);
    }
}

/// Starts the push worker. Requests are coalesced per device.
pub fn spawn(pool: PgPool, config: PushConfig) -> Pusher {
    let fcm = config.fcm_service_account.as_deref().and_then(|path| match Fcm::load(path) {
        Ok(fcm) => {
            tracing::info!("FCM push fallback enabled");
            Some(fcm)
        }
        Err(err) => {
            tracing::error!(%err, "FCM disabled");
            None
        }
    });
    let http = reqwest::Client::builder()
        .timeout(SEND_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    let interval = config.min_interval;
    let sender = Arc::new(Sender { pool, config, http, fcm });
    let (tx, mut rx) = mpsc::unbounded_channel::<Uuid>();
    tokio::spawn(async move {
        // device -> (last push, another one is due)
        let mut state: HashMap<Uuid, (Instant, bool)> = HashMap::new();
        let mut tick = tokio::time::interval(interval.min(Duration::from_secs(1)));
        loop {
            tokio::select! {
                received = rx.recv() => {
                    let Some(device_id) = received else { return };
                    match state.get_mut(&device_id) {
                        Some((last, due)) if last.elapsed() < interval => *due = true,
                        _ => {
                            state.insert(device_id, (Instant::now(), false));
                            let sender = sender.clone();
                            tokio::spawn(async move { sender.send(device_id).await });
                        }
                    }
                }
                _ = tick.tick() => {
                    let now = Instant::now();
                    for (device_id, (last, due)) in state.iter_mut() {
                        if *due && now.duration_since(*last) >= interval {
                            *last = now;
                            *due = false;
                            let (sender, device_id) = (sender.clone(), *device_id);
                            tokio::spawn(async move { sender.send(device_id).await });
                        }
                    }
                    state.retain(|_, (last, due)| *due || last.elapsed() < interval * 6);
                }
            }
        }
    });
    Pusher { tx }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_addresses_are_not_public() {
        for ip in [
            "10.0.0.1",
            "192.168.1.5",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn endpoint_urls_must_be_https() {
        let config = PushConfig::default();
        assert!(check_endpoint_url("https://ntfy.example.org/up123", &config).is_ok());
        assert!(check_endpoint_url("http://ntfy.example.org/up123", &config).is_err());
        assert!(check_endpoint_url("https://user:pw@ntfy.example.org/", &config).is_err());
        assert!(check_endpoint_url("file:///etc/passwd", &config).is_err());
        let lax = PushConfig { allow_http: true, ..PushConfig::default() };
        assert!(check_endpoint_url("http://ntfy.local/up", &lax).is_ok());
    }
}
