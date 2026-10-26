//! Admin side of the client (ADR-0006).
//!
//! The admin key is an Ed25519 key pair separate from the chat device: it
//! lives in `admin.ssmc` in the profile directory, sealed with its own unlock
//! pattern. The server only knows the public key (registered in the TUI).
//! [`AdminClient`] logs in with a signed challenge and signs a fresh
//! confirmation for every destructive action.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssm_core::Pattern;
use ssm_core::container::{HardwareSecret, KdfParams, UnlockedContainer};
use ssm_proto::api::{
    AccountInfo, AccountRoleRequest, AccountStatusRequest, AddAdminKeyRequest, AdminDeviceInfo, AdminJob,
    AdminKeyLookup, AdminOutcome, AdminOverview, AdminSessionRequest, AuditEvent, ChallengeResponse, ConfirmRequest,
    ContentSummary, CreateAccountRequest, DeleteJobInfo, DeviceAction, DeviceStatus, InviteResponse, MassDeleteRequest,
    SessionResponse,
};
use ssm_proto::{B64, signing};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::{Api, http_client};
use crate::error::{ClientError, ClientResult};

const ADMIN_CONTAINER: &str = "admin.ssmc";
const RENEW_MARGIN: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
struct StoredAdminKey {
    secret: B64,
}

/// The unlocked admin key. Dropping it removes the secret from memory.
pub struct AdminKey {
    signing: SigningKey,
}

impl std::fmt::Debug for AdminKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminKey").field("public_key", &self.public_key()).finish_non_exhaustive()
    }
}

impl AdminKey {
    fn path(profile_dir: &Path) -> PathBuf {
        profile_dir.join(ADMIN_CONTAINER)
    }

    pub fn exists(profile_dir: &Path) -> bool {
        Self::path(profile_dir).exists()
    }

    /// Creates a new admin key protected by `pattern` (use a different one
    /// than for the chat).
    pub fn create(
        profile_dir: &Path,
        pattern: &Pattern,
        params: KdfParams,
        hardware: Option<&HardwareSecret>,
    ) -> ClientResult<Self> {
        if Self::exists(profile_dir) {
            return Err(ClientError::Profile("an admin key already exists for this account".into()));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|e| ClientError::Profile(format!("random number generator: {e}")))?;
        let signing = SigningKey::from_bytes(&secret);
        let container = UnlockedContainer::create(pattern, params, hardware)?;
        let stored = Zeroizing::new(
            serde_json::to_vec(&StoredAdminKey { secret: B64(secret.to_vec()) })
                .map_err(|e| ClientError::Profile(e.to_string()))?,
        );
        let sealed = container.seal(&stored)?;
        let path = Self::path(profile_dir);
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            file.write_all(&sealed)?;
            file.sync_all()?;
        }
        std::fs::rename(tmp, path)?;
        Ok(Self { signing })
    }

    pub fn open(profile_dir: &Path, pattern: &Pattern, hardware: Option<&HardwareSecret>) -> ClientResult<Self> {
        let sealed = std::fs::read(Self::path(profile_dir))?;
        let (_, plaintext) = UnlockedContainer::open(&sealed, pattern, hardware)?;
        let stored: StoredAdminKey =
            serde_json::from_slice(&plaintext).map_err(|e| ClientError::Profile(e.to_string()))?;
        let secret: Zeroizing<[u8; 32]> =
            Zeroizing::new(stored.secret.to_array().ok_or_else(|| ClientError::Profile("admin key length".into()))?);
        Ok(Self { signing: SigningKey::from_bytes(&secret) })
    }

    /// To register in the TUI (Accounts → k).
    pub fn public_key(&self) -> String {
        B64::encode(&self.signing.verifying_key().to_bytes())
    }

    /// Deletes the admin key file (e.g. after the role was removed).
    pub fn remove(profile_dir: &Path) -> ClientResult<()> {
        Ok(std::fs::remove_file(Self::path(profile_dir))?)
    }
}

struct Session {
    token: String,
    valid_until: Instant,
}

pub struct AdminClient {
    http: reqwest::Client,
    base_url: String,
    key: AdminKey,
    key_id: Uuid,
    session: Mutex<Option<Session>>,
}

impl AdminClient {
    /// Finds the registered key and logs in. Fails with `not-found` while the
    /// key is not registered on the server yet.
    pub async fn connect(base_url: &str, key: AdminKey) -> ClientResult<Self> {
        let http = http_client()?;
        let base_url = base_url.trim_end_matches('/').to_owned();
        // base64url contains only URL-safe characters.
        let response =
            http.get(format!("{base_url}/v1/admin/keys/lookup?public_key={}", key.public_key())).send().await?;
        if !response.status().is_success() {
            return Err(Api::error(response).await);
        }
        let lookup: AdminKeyLookup = response.json().await?;
        let client = Self { http, base_url, key, key_id: lookup.admin_key_id, session: Mutex::new(None) };
        client.token().await?;
        Ok(client)
    }

    async fn request<B: Serialize + ?Sized>(
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

    async fn public<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: Option<&B>,
    ) -> ClientResult<T> {
        let response = self.request(Method::POST, path, None, body).await?;
        if !response.status().is_success() {
            return Err(Api::error(response).await);
        }
        Ok(response.json().await?)
    }

    async fn login(&self) -> ClientResult<Session> {
        let challenge: ChallengeResponse = self.public("/v1/admin/auth/challenge", None::<&()>).await?;
        let signature = signing::sign(&self.key.signing, &signing::admin_auth_message(&challenge.nonce.0, self.key_id));
        let request = AdminSessionRequest {
            admin_key_id: self.key_id,
            nonce: challenge.nonce,
            signature: B64(signature.to_vec()),
        };
        let session: SessionResponse = self.public("/v1/admin/auth/session", Some(&request)).await?;
        Ok(Session { token: session.token, valid_until: Instant::now() + Duration::from_secs(session.expires_in_secs) })
    }

    async fn token(&self) -> ClientResult<String> {
        let mut session = self.session.lock().await;
        if session.as_ref().is_none_or(|s| s.valid_until.saturating_duration_since(Instant::now()) < RENEW_MARGIN) {
            *session = Some(self.login().await?);
        }
        Ok(session.as_ref().expect("session set").token.clone())
    }

    async fn call<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> ClientResult<T> {
        for attempt in 0..2 {
            let token = self.token().await?;
            let response = self.request(method.clone(), path, Some(&token), body).await?;
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                *self.session.lock().await = None;
                continue;
            }
            if !response.status().is_success() {
                return Err(Api::error(response).await);
            }
            return Ok(response.json().await?);
        }
        unreachable!("loop returns on the second attempt")
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> ClientResult<T> {
        self.call(Method::GET, path, None::<&()>).await
    }

    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(&self, path: &str, body: &B) -> ClientResult<T> {
        self.call(Method::POST, path, Some(body)).await
    }

    /// Fresh signature for a destructive `action` on `target` (ADR-0006).
    async fn confirm(&self, action: &str, target: &str) -> ClientResult<ConfirmRequest> {
        let challenge: ChallengeResponse = self.post("/v1/admin/confirm/challenge", &()).await?;
        let message = signing::admin_confirm_message(&challenge.nonce.0, action, target);
        Ok(ConfirmRequest {
            nonce: challenge.nonce,
            signature: B64(signing::sign(&self.key.signing, &message).to_vec()),
        })
    }

    pub async fn overview(&self) -> ClientResult<AdminOverview> {
        self.get("/v1/admin/overview").await
    }

    pub async fn devices(&self, status: Option<DeviceStatus>) -> ClientResult<Vec<AdminDeviceInfo>> {
        match status {
            Some(status) => self.get(&format!("/v1/admin/devices?status={}", status.as_str())).await,
            None => self.get("/v1/admin/devices").await,
        }
    }

    /// Revoke and reject delete the device; revoke is confirmed by signature.
    pub async fn device_action(&self, device_id: Uuid, action: DeviceAction) -> ClientResult<AdminDeviceInfo> {
        let path = format!("/v1/admin/devices/{device_id}/{}", action.as_str());
        if action.is_destructive() {
            let confirm = self.confirm(action.as_str(), &format!("device:{device_id}")).await?;
            self.post(&path, &confirm).await
        } else {
            self.call(Method::POST, &path, None::<&()>).await
        }
    }

    pub async fn accounts(&self) -> ClientResult<Vec<AccountInfo>> {
        self.get("/v1/admin/accounts").await
    }

    pub async fn create_account(&self, username: &str) -> ClientResult<InviteResponse> {
        self.post("/v1/admin/accounts", &CreateAccountRequest { username: username.to_owned() }).await
    }

    pub async fn new_invite(&self, account_id: Uuid) -> ClientResult<InviteResponse> {
        self.post(&format!("/v1/admin/accounts/{account_id}/invites"), &()).await
    }

    pub async fn set_account_locked(&self, account_id: Uuid, locked: bool) -> ClientResult<String> {
        let action = if locked { "disable-account" } else { "enable-account" };
        let confirm = self.confirm(action, &format!("account:{account_id}")).await?;
        let outcome: AdminOutcome = self
            .post(
                &format!("/v1/admin/accounts/{account_id}/status"),
                &AccountStatusRequest { disabled: locked, confirm },
            )
            .await?;
        Ok(outcome.message)
    }

    pub async fn set_admin_role(&self, account_id: Uuid, admin: bool) -> ClientResult<String> {
        let action = if admin { "grant-admin" } else { "revoke-admin" };
        let confirm = self.confirm(action, &format!("account:{account_id}")).await?;
        let outcome: AdminOutcome =
            self.post(&format!("/v1/admin/accounts/{account_id}/role"), &AccountRoleRequest { admin, confirm }).await?;
        Ok(outcome.message)
    }

    pub async fn add_admin_key(&self, account_id: Uuid, public_key: &str) -> ClientResult<String> {
        let key = B64::decode(public_key.trim()).ok_or_else(|| ClientError::Protocol("invalid public key".into()))?;
        let confirm = self.confirm("add-admin-key", &format!("account:{account_id}")).await?;
        let request = AddAdminKeyRequest { public_key: B64(key), confirm };
        let outcome: AdminOutcome = self.post(&format!("/v1/admin/accounts/{account_id}/admin-keys"), &request).await?;
        Ok(outcome.message)
    }

    /// Deletes the account completely, including its messages for everyone.
    pub async fn delete_account(&self, account_id: Uuid) -> ClientResult<String> {
        let confirm = self.confirm("delete-account", &format!("account:{account_id}")).await?;
        let outcome: AdminOutcome = self.post(&format!("/v1/admin/accounts/{account_id}/delete"), &confirm).await?;
        Ok(outcome.message)
    }

    pub async fn content_summary(&self, account_id: Uuid) -> ClientResult<ContentSummary> {
        self.get(&format!("/v1/admin/accounts/{account_id}/content-summary")).await
    }

    /// Deletes everything the account sent, for everyone (asynchronous job).
    pub async fn delete_all_content(&self, account_id: Uuid) -> ClientResult<DeleteJobInfo> {
        let confirm = self.confirm("delete-all-content", &format!("account:{account_id}")).await?;
        let request =
            MassDeleteRequest { operation_id: Uuid::new_v4(), nonce: confirm.nonce, signature: confirm.signature };
        self.post(&format!("/v1/admin/accounts/{account_id}/delete-all-content"), &request).await
    }

    pub async fn jobs(&self) -> ClientResult<Vec<AdminJob>> {
        self.get("/v1/admin/delete-jobs").await
    }

    pub async fn audit(&self) -> ClientResult<Vec<AuditEvent>> {
        self.get("/v1/admin/audit-events?limit=100").await
    }
}
