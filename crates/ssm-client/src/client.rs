//! High-level device client: enrollment, unlock, sync, messaging.
//!
//! [`LockedClient`] can do what is allowed without the pattern (device status,
//! notification hint). [`Client`] holds the opened key container and the
//! Olm/Megolm state; dropping or locking it removes them from memory.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use ssm_core::container::{HardwareSecret, KdfParams, UnlockedContainer};
use ssm_core::e2ee::{ClaimedKey, CryptoStore, E2eeError, RecipientDevice};
use ssm_core::{Pattern, lockout};
use ssm_proto::api::{
    AccountLookup, AddMemberRequest, ChallengeResponse, ClaimKeysRequest, ClaimKeysResponse, ConversationInfo,
    ConversationKind, CreateConversationRequest, DeleteJobInfo, DeleteRequest, DeviceStatus, DeviceStatusResponse,
    EnrollRequest, EnrollResponse, EventBody, EventsResponse, MessageBody, MessagesPage, NotificationHint, OneTimeKey,
    PeerDevice, RetentionRequest, SendMessageRequest, SendMessageResponse, SendToDeviceRequest, SendToDeviceResponse,
    ToDeviceMessage, UploadKeysRequest, UploadKeysResponse,
};
use ssm_proto::{B64, signing};
use uuid::Uuid;

use crate::api::Api;
use crate::content::{Content, DisplayBody, DisplayMessage, MediaInfo, MediaRef};
use crate::error::{ClientError, ClientResult};
use crate::profile::{Profile, ProfileData, ProfileLock};

/// Keep at least this many one-time keys on the server.
const MIN_ONE_TIME_KEYS: u32 = 25;
const TARGET_ONE_TIME_KEYS: u32 = 50;
const EVENTS_PAGE: u32 = 500;

pub enum EnrollWith {
    /// First device of an account.
    Invite(String),
    /// Further device of an existing account.
    Username(String),
}

/// Something the UI should react to after [`Client::sync`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    NewMessage { conversation_id: Uuid, seq: i64 },
    MessageDeleted { conversation_id: Uuid, message_id: Uuid },
    ConversationUpdated { conversation_id: Uuid },
    KeyReceived { conversation_id: Uuid },
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn new_signing_key() -> ClientResult<SigningKey> {
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut()).map_err(|e| ClientError::Profile(format!("random number generator: {e}")))?;
    Ok(SigningKey::from_bytes(&secret))
}

async fn set_push_endpoint(api: &Api, kind: ssm_proto::api::PushKind, endpoint: &str) -> ClientResult<()> {
    let request = ssm_proto::api::PushEndpointRequest { kind, endpoint: endpoint.to_owned() };
    let _: DeviceStatusResponse = api.put("/v1/push-endpoint", &request).await?;
    Ok(())
}

async fn fetch_status(api: &Api) -> ClientResult<DeviceStatusResponse> {
    api.get("/v1/devices/status").await
}

/// A failed unlock hands the locked client back for the next attempt.
#[derive(Debug)]
pub struct UnlockFailed {
    pub locked: Box<LockedClient>,
    pub error: ClientError,
}

impl UnlockFailed {
    fn new(locked: LockedClient, error: ClientError) -> Self {
        Self { locked: Box::new(locked), error }
    }
}

pub struct LockedClient {
    profile: Profile,
    data: ProfileData,
    api: Api,
    _lock: ProfileLock,
}

impl std::fmt::Debug for LockedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedClient").field("device_id", &self.data.device_id).finish_non_exhaustive()
    }
}

impl LockedClient {
    /// Opens a profile and locks it against use by another process.
    pub fn open(dir: impl Into<std::path::PathBuf>) -> ClientResult<Self> {
        let profile = Profile::at(dir)?;
        let lock = ProfileLock::acquire(profile.dir())?;
        let data = profile.load()?;
        let api = Api::new(&data.server_url, profile.load_device_key()?, data.device_id)?;
        Ok(Self { profile, data, api, _lock: lock })
    }

    pub fn dir(&self) -> &std::path::Path {
        self.profile.dir()
    }

    /// Where content-free wake-ups go (works while locked, e.g. from a push
    /// service started without the UI).
    pub async fn set_push_endpoint(&self, kind: ssm_proto::api::PushKind, endpoint: &str) -> ClientResult<()> {
        set_push_endpoint(&self.api, kind, endpoint).await
    }

    pub async fn remove_push_endpoint(&self) -> ClientResult<()> {
        let _: DeviceStatusResponse = self.api.delete("/v1/push-endpoint").await?;
        Ok(())
    }

    /// Signs this device out of its account for good (the server deletes
    /// it). Afterwards remove the profile with `ProfileStore::remove`.
    pub async fn unregister(&self) -> ClientResult<()> {
        let _: ssm_proto::api::DeviceRemoved = self.api.delete("/v1/devices/self").await?;
        Ok(())
    }

    pub fn data(&self) -> &ProfileData {
        &self.data
    }

    /// Works while pending approval and while locked.
    pub async fn device_status(&self) -> ClientResult<DeviceStatus> {
        Ok(fetch_status(&self.api).await?.status)
    }

    /// For notifications while locked: pending count and the sender initial.
    pub async fn notification_hint(&self) -> ClientResult<NotificationHint> {
        self.api.get("/v1/notifications/hint").await
    }

    /// How long the UI must wait before the next unlock attempt.
    pub fn unlock_delay(&self) -> Duration {
        lockout::delay_after_failures(self.data.failed_unlocks)
    }

    /// Opens the key container. Wrong patterns are counted for the delay policy.
    pub fn unlock(mut self, pattern: &Pattern, hardware: Option<&HardwareSecret>) -> Result<Client, UnlockFailed> {
        let sealed = match self.profile.load_container() {
            Ok(sealed) => sealed,
            Err(err) => return Err(UnlockFailed::new(self, err)),
        };
        match UnlockedContainer::open(&sealed, pattern, hardware) {
            Ok((container, plaintext)) => {
                let store = match CryptoStore::from_bytes(&plaintext) {
                    Ok(store) => store,
                    Err(err) => return Err(UnlockFailed::new(self, err.into())),
                };
                if self.data.failed_unlocks != 0 {
                    self.data.failed_unlocks = 0;
                    if let Err(err) = self.profile.save(&self.data) {
                        return Err(UnlockFailed::new(self, err));
                    }
                }
                Ok(Client {
                    _lock: self._lock,
                    profile: self.profile,
                    data: self.data,
                    api: self.api,
                    container,
                    store,
                    check_one_time_keys: true,
                })
            }
            Err(err) => {
                self.data.failed_unlocks = self.data.failed_unlocks.saturating_add(1);
                let _ = self.profile.save(&self.data);
                Err(UnlockFailed::new(self, err.into()))
            }
        }
    }
}

pub struct Client {
    _lock: ProfileLock,
    profile: Profile,
    data: ProfileData,
    api: Api,
    container: UnlockedContainer,
    store: CryptoStore,
    check_one_time_keys: bool,
}

impl Client {
    /// Creates a device identity and key container, and registers the device
    /// as pending. The returned client is unlocked; most calls fail with
    /// `device-pending` until an admin approves the device.
    pub async fn enroll(
        dir: impl Into<std::path::PathBuf>,
        server_url: &str,
        with: EnrollWith,
        display_name: &str,
        pattern: &Pattern,
        params: KdfParams,
        hardware: Option<&HardwareSecret>,
    ) -> ClientResult<Self> {
        let profile = Profile::at(dir)?;
        if profile.exists() {
            return Err(ClientError::Profile("a profile already exists in this directory".into()));
        }
        let lock = ProfileLock::acquire(profile.dir())?;
        let signing_key = new_signing_key()?;
        let mut api = Api::new(server_url, signing_key, None)?;
        let mut store = CryptoStore::new();

        let challenge: ChallengeResponse =
            api.public(reqwest::Method::POST, "/v1/devices/enroll/challenge", None::<&()>).await?;
        let public = api.signing_key().verifying_key().to_bytes();
        let message =
            signing::enroll_message(&challenge.nonce.0, &public, &store.identity_key(), &store.fingerprint_key());
        let (invite_code, username) = match with {
            EnrollWith::Invite(code) => (Some(code), None),
            EnrollWith::Username(name) => (None, Some(name)),
        };
        let request = EnrollRequest {
            invite_code,
            username: username.clone(),
            display_name: display_name.to_owned(),
            signing_key: B64(public.to_vec()),
            olm_identity_key: B64(store.identity_key().to_vec()),
            olm_fingerprint_key: B64(store.fingerprint_key().to_vec()),
            nonce: challenge.nonce,
            signature: B64(signing::sign(api.signing_key(), &message).to_vec()),
        };
        let enrolled: EnrollResponse = api.public(reqwest::Method::POST, "/v1/devices/enroll", Some(&request)).await?;
        api.set_device_id(enrolled.device_id);
        store.set_device_id(enrolled.device_id);

        let container = UnlockedContainer::create(pattern, params, hardware)?;
        let data = ProfileData {
            server_url: api.base_url().to_owned(),
            username,
            display_name: display_name.to_owned(),
            device_id: Some(enrolled.device_id),
            account_id: None,
            event_cursor: 0,
            failed_unlocks: 0,
        };
        profile.save_device_key(api.signing_key())?;
        let mut client = Self { _lock: lock, profile, data, api, container, store, check_one_time_keys: true };
        client.save()?;
        client.profile.save(&client.data)?;
        // Publish keys while still pending: others can start sessions with
        // this device as soon as it is approved, even before it comes online.
        // Best effort, the first sync checks again.
        let _ = client.top_up_keys().await;
        Ok(client)
    }

    /// Drops the opened container and all keys from memory.
    pub fn lock(self) -> LockedClient {
        LockedClient { profile: self.profile, data: self.data, api: self.api, _lock: self._lock }
    }

    pub fn data(&self) -> &ProfileData {
        &self.data
    }

    pub fn dir(&self) -> &std::path::Path {
        self.profile.dir()
    }

    pub fn device_id(&self) -> Uuid {
        self.data.device_id.expect("enrolled client has a device id")
    }

    pub fn account_id(&self) -> Option<Uuid> {
        self.data.account_id
    }

    pub fn api(&self) -> &Api {
        &self.api
    }

    /// WebSocket URL and a fresh token for [`crate::WakeChannel::connect`].
    pub async fn realtime_credentials(&self) -> ClientResult<(String, String)> {
        Ok((self.api.websocket_url(), self.api.token().await?))
    }

    /// Olm fingerprint key as shown to the admin when approving the device.
    pub fn fingerprint(&self) -> String {
        let encoded = B64::encode(&self.store.fingerprint_key());
        encoded.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
    }

    pub async fn notification_hint(&self) -> ClientResult<NotificationHint> {
        self.api.get("/v1/notifications/hint").await
    }

    /// Display name of a device's own account, for UI headers.
    pub fn username(&self) -> Option<&str> {
        self.data.username.as_deref()
    }

    /// Persists the crypto state into the container. Called after every change.
    fn save(&self) -> ClientResult<()> {
        let sealed = self.container.seal(&self.store.to_bytes())?;
        self.profile.save_container(&sealed)
    }

    /// Status, and learns account id and username on the way.
    pub async fn device_status(&mut self) -> ClientResult<DeviceStatus> {
        let status = fetch_status(&self.api).await?;
        if self.data.account_id != Some(status.account_id) || self.data.username.as_deref() != Some(&status.username) {
            self.data.account_id = Some(status.account_id);
            self.data.username = Some(status.username);
            self.profile.save(&self.data)?;
        }
        Ok(status.status)
    }

    pub async fn set_push_endpoint(&self, kind: ssm_proto::api::PushKind, endpoint: &str) -> ClientResult<()> {
        set_push_endpoint(&self.api, kind, endpoint).await
    }

    /// Changes the unlock pattern (re-wraps the master key).
    pub fn change_pattern(
        &mut self,
        pattern: &Pattern,
        params: KdfParams,
        hardware: Option<&HardwareSecret>,
    ) -> ClientResult<()> {
        self.container.change_pattern(pattern, params, hardware)?;
        self.save()
    }

    /// Keeps enough one-time keys (and a fallback key) on the server.
    pub async fn top_up_keys(&mut self) -> ClientResult<u32> {
        let current: UploadKeysResponse = self
            .api
            .post("/v1/keys/one-time", &UploadKeysRequest { one_time_keys: vec![], fallback_key: None })
            .await?;
        if current.one_time_key_count >= MIN_ONE_TIME_KEYS {
            return Ok(current.one_time_key_count);
        }
        let new = (TARGET_ONE_TIME_KEYS - current.one_time_key_count) as usize;
        let keys = self.store.generate_one_time_keys(new);
        let fallback = self.store.generate_fallback_key();
        self.save()?;
        let request = UploadKeysRequest {
            one_time_keys: keys
                .iter()
                .map(|(id, k)| OneTimeKey { key_id: id.clone(), public_key: B64(k.to_vec()) })
                .collect(),
            fallback_key: fallback.map(|(id, k)| OneTimeKey { key_id: id, public_key: B64(k.to_vec()) }),
        };
        let uploaded: UploadKeysResponse = self.api.post("/v1/keys/one-time", &request).await?;
        self.store.mark_keys_published();
        self.save()?;
        Ok(uploaded.one_time_key_count)
    }

    /// Fetches and processes all pending events. Received keys are stored;
    /// everything else is returned for the UI.
    pub async fn sync(&mut self) -> ClientResult<Vec<Update>> {
        if self.check_one_time_keys {
            self.top_up_keys().await?;
            self.check_one_time_keys = false;
        }
        let mut updates = Vec::new();
        loop {
            let page: EventsResponse =
                self.api.get(&format!("/v1/events?since={}&limit={EVENTS_PAGE}", self.data.event_cursor)).await?;
            // The server deletes events only when a later request acknowledges
            // them, so the loop ends with an empty page that acknowledges all.
            if page.events.is_empty() {
                break;
            }
            let mut store_changed = false;
            for event in page.events {
                match event.body {
                    EventBody::ToDevice { sender_device_id, sender_identity_key, message_type, ciphertext } => {
                        let Some(identity) = sender_identity_key.to_array() else { continue };
                        if message_type == 0 {
                            self.check_one_time_keys = true;
                        }
                        match self.store.receive_to_device(
                            sender_device_id,
                            identity,
                            message_type,
                            &ciphertext.0,
                            now(),
                        ) {
                            Ok(ssm_core::e2ee::Received::GroupKey { conversation_id, .. }) => {
                                store_changed = true;
                                updates.push(Update::KeyReceived { conversation_id });
                            }
                            Err(err) => tracing::warn!(%sender_device_id, error = %err, "dropping to-device message"),
                        }
                    }
                    EventBody::Message { conversation_id, seq } => {
                        updates.push(Update::NewMessage { conversation_id, seq })
                    }
                    EventBody::MessageDeleted { conversation_id, message_id } => {
                        updates.push(Update::MessageDeleted { conversation_id, message_id })
                    }
                    EventBody::ConversationUpdated { conversation_id } => {
                        updates.push(Update::ConversationUpdated { conversation_id })
                    }
                }
            }
            if store_changed {
                self.save()?;
            }
            if page.next_since != self.data.event_cursor {
                self.data.event_cursor = page.next_since;
                self.profile.save(&self.data)?;
            }
        }
        if self.check_one_time_keys {
            self.top_up_keys().await?;
            self.check_one_time_keys = false;
        }
        Ok(updates)
    }

    pub async fn conversations(&self) -> ClientResult<Vec<ConversationInfo>> {
        self.api.get("/v1/conversations").await
    }

    pub async fn conversation(&self, id: Uuid) -> ClientResult<ConversationInfo> {
        self.api.get(&format!("/v1/conversations/{id}")).await
    }

    pub async fn lookup(&self, username: &str) -> ClientResult<AccountLookup> {
        self.api.get(&format!("/v1/accounts/by-username/{username}")).await
    }

    pub async fn create_conversation(
        &self,
        kind: ConversationKind,
        members: Vec<Uuid>,
        retention_days: Option<u16>,
    ) -> ClientResult<ConversationInfo> {
        self.api.post("/v1/conversations", &CreateConversationRequest { kind, members, retention_days }).await
    }

    pub async fn add_member(&self, conversation: Uuid, account_id: Uuid) -> ClientResult<ConversationInfo> {
        self.api.post(&format!("/v1/conversations/{conversation}/members"), &AddMemberRequest { account_id }).await
    }

    pub async fn remove_member(&self, conversation: Uuid, account_id: Uuid) -> ClientResult<ConversationInfo> {
        self.api.delete(&format!("/v1/conversations/{conversation}/members/{account_id}")).await
    }

    pub async fn set_retention(&self, conversation: Uuid, days: u16) -> ClientResult<ConversationInfo> {
        self.api.put(&format!("/v1/conversations/{conversation}/retention"), &RetentionRequest { days }).await
    }

    pub async fn delete_for_all(&self, message_id: Uuid) -> ClientResult<DeleteJobInfo> {
        let request = DeleteRequest { operation_id: Uuid::new_v4() };
        self.api.post(&format!("/v1/messages/{message_id}/delete-for-all"), &request).await
    }

    /// All active devices of all active members (including this account's
    /// other devices).
    async fn recipients(&self, conversation: &ConversationInfo) -> ClientResult<Vec<RecipientDevice>> {
        let mut recipients = Vec::new();
        for member in conversation.members.iter().filter(|m| m.status == "active") {
            let devices: Vec<PeerDevice> = self.api.get(&format!("/v1/accounts/{}/devices", member.account_id)).await?;
            for device in devices {
                let identity_key = device
                    .olm_identity_key
                    .to_array()
                    .ok_or_else(|| ClientError::Protocol("identity key length".into()))?;
                recipients.push(RecipientDevice { device_id: device.device_id, identity_key });
            }
        }
        Ok(recipients)
    }

    /// Encrypts and sends a text message.
    pub async fn send_text(&mut self, conversation_id: Uuid, text: &str) -> ClientResult<SendMessageResponse> {
        self.send_content(conversation_id, &Content::Text { text: text.to_owned() }, Vec::new()).await
    }

    async fn upload_encrypted(&self, conversation_id: Uuid, plaintext: &[u8]) -> ClientResult<MediaRef> {
        let (key, sealed) = ssm_core::media::encrypt(plaintext).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let size = plaintext.len() as u64;
        let uploaded: ssm_proto::api::MediaUploaded =
            self.api.post_bytes(&format!("/v1/conversations/{conversation_id}/media"), sealed).await?;
        Ok(MediaRef { media_id: uploaded.media_id, key: B64(key.to_vec()), size })
    }

    /// Encrypts the file (and an optional preview, e.g. a small image) on
    /// this device, uploads both and sends the message carrying their keys.
    pub async fn send_media(
        &mut self,
        conversation_id: Uuid,
        name: &str,
        mime: &str,
        data: &[u8],
        preview: Option<&[u8]>,
        caption: Option<&str>,
    ) -> ClientResult<SendMessageResponse> {
        let original = self.upload_encrypted(conversation_id, data).await?;
        let preview = match preview {
            Some(bytes) => Some(self.upload_encrypted(conversation_id, bytes).await?),
            None => None,
        };
        let media_ids = std::iter::once(original.media_id).chain(preview.as_ref().map(|p| p.media_id)).collect();
        let info = MediaInfo {
            kind: crate::content::MediaKind::from_mime(mime),
            name: name.to_owned(),
            mime: mime.to_owned(),
            original,
            preview,
            caption: caption.map(str::to_owned),
        };
        self.send_content(conversation_id, &Content::Media(info), media_ids).await
    }

    /// Downloads and decrypts a media object (in memory only).
    pub async fn fetch_media(&self, media: &MediaRef) -> ClientResult<zeroize::Zeroizing<Vec<u8>>> {
        let sealed = self.api.get_bytes(&format!("/v1/media/{}", media.media_id)).await?;
        let key: [u8; 32] = media.key.to_array().ok_or_else(|| ClientError::Protocol("media key length".into()))?;
        ssm_core::media::decrypt(&key, &sealed).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// Encrypts any content with the group session (sharing or rotating it
    /// first when needed) and sends it.
    async fn send_content(
        &mut self,
        conversation_id: Uuid,
        content: &Content,
        media_ids: Vec<Uuid>,
    ) -> ClientResult<SendMessageResponse> {
        let content = serde_json::to_vec(content).map_err(|e| ClientError::Protocol(e.to_string()))?;
        let conversation = self.conversation(conversation_id).await?;
        let recipients = self.recipients(&conversation).await?;

        let need = self.store.devices_needing_keys(conversation_id, &recipients, now())?;
        let claimed = if need.is_empty() {
            Vec::new()
        } else {
            let response: ClaimKeysResponse =
                self.api.post("/v1/keys/claim", &ClaimKeysRequest { device_ids: need }).await?;
            response
                .keys
                .into_iter()
                .filter_map(|k| Some(ClaimedKey { device_id: k.device_id, one_time_key: k.public_key.to_array()? }))
                .collect()
        };
        let share = self.store.share_group_session(conversation_id, &recipients, &claimed, now())?;
        self.save()?;
        if !share.messages.is_empty() {
            let messages = share
                .messages
                .into_iter()
                .map(|m| ToDeviceMessage {
                    device_id: m.device_id,
                    message_type: m.message_type,
                    ciphertext: B64(m.ciphertext),
                })
                .collect();
            let _: SendToDeviceResponse = self.api.post("/v1/to-device", &SendToDeviceRequest { messages }).await?;
        }

        let encrypted = self.store.encrypt(conversation_id, &content)?;
        self.save()?;
        let request = SendMessageRequest {
            client_id: Uuid::new_v4(),
            session_id: encrypted.session_id,
            ciphertext: B64(encrypted.ciphertext),
            media_ids,
        };
        self.api.post(&format!("/v1/conversations/{conversation_id}/messages"), &request).await
    }

    fn display(&mut self, conversation_id: Uuid, page: MessagesPage) -> Vec<DisplayMessage> {
        page.messages
            .into_iter()
            .map(|item| {
                let body = match item.body {
                    MessageBody::Encrypted { session_id, ciphertext } => match item.sender_device_id {
                        None => DisplayBody::Undecryptable("sender device no longer exists".into()),
                        Some(sender) => match self.store.decrypt(conversation_id, sender, &session_id, &ciphertext.0) {
                            Ok(plaintext) => match serde_json::from_slice::<Content>(&plaintext) {
                                Ok(Content::Text { text }) => DisplayBody::Text(text),
                                Ok(Content::Media(info)) => DisplayBody::Media(info),
                                Err(_) => DisplayBody::Undecryptable("unknown content".into()),
                            },
                            Err(E2eeError::UnknownSession) => DisplayBody::Unavailable,
                            Err(err) => DisplayBody::Undecryptable(err.to_string()),
                        },
                    },
                    MessageBody::Deleted { deleted_by, .. } => DisplayBody::Deleted { by: deleted_by },
                    MessageBody::System { notice } => DisplayBody::Notice(notice),
                };
                DisplayMessage {
                    message_id: item.message_id,
                    seq: item.seq,
                    sender_account_id: item.sender_account_id,
                    sender_device_id: item.sender_device_id,
                    created_at: item.created_at,
                    expires_at: item.expires_at,
                    body,
                }
            })
            .collect()
    }

    /// One page (≤ 100), newest first, decrypted in memory. Returns the cursor
    /// for the next older page.
    pub async fn messages(
        &mut self,
        conversation_id: Uuid,
        before: Option<i64>,
    ) -> ClientResult<(Vec<DisplayMessage>, Option<i64>)> {
        let path = match before {
            Some(before) => format!("/v1/conversations/{conversation_id}/messages?before={before}"),
            None => format!("/v1/conversations/{conversation_id}/messages"),
        };
        let page: MessagesPage = self.api.get(&path).await?;
        let next = page.next_before;
        Ok((self.display(conversation_id, page), next))
    }

    /// Messages newer than `after`, oldest first.
    pub async fn messages_after(&mut self, conversation_id: Uuid, after: i64) -> ClientResult<Vec<DisplayMessage>> {
        let page: MessagesPage =
            self.api.get(&format!("/v1/conversations/{conversation_id}/messages?after={after}")).await?;
        Ok(self.display(conversation_id, page))
    }
}
