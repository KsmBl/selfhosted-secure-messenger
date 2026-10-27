//! UniFFI bindings over `ssm-client` for the Android app.
//!
//! One [`SsmSession`] per profile directory. It is locked (only status and
//! notification hint available) or unlocked (keys in memory). Ids cross the
//! boundary as strings; display texts are prepared here so all clients show
//! the same wording.

mod admin;

use std::collections::HashMap;
use std::sync::Arc;

use ssm_client::{Client, ClientError, DisplayBody, EnrollWith, LockedClient, MediaInfo, MediaKind, Update};
use ssm_core::container::HardwareSecret;
use ssm_core::{KdfParams, Pattern};
use ssm_proto::api::{ConversationInfo, ConversationKind, SystemNotice};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// Progress messages to logcat (Android) or stderr. Never secrets.
fn trace(message: &str) {
    #[cfg(target_os = "android")]
    {
        unsafe extern "C" {
            fn __android_log_write(priority: i32, tag: *const std::ffi::c_char, text: *const std::ffi::c_char) -> i32;
        }
        if let Ok(text) = std::ffi::CString::new(message) {
            // SAFETY: both pointers are valid NUL-terminated strings for the call.
            unsafe {
                __android_log_write(4, c"ssm-ffi".as_ptr(), text.as_ptr());
            }
        }
    }
    #[cfg(not(target_os = "android"))]
    eprintln!("ssm-ffi: {message}");
}

const KDF_TARGET: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    #[error("The app is locked.")]
    Locked,
    #[error("Wrong pattern.")]
    WrongPattern,
    #[error("{0}")]
    InvalidPattern(String),
    #[error("This device is still waiting for approval.")]
    NotApproved,
    #[error("This device was disabled or revoked by an administrator.")]
    DeviceInactive,
    #[error("Not found.")]
    NotFound,
    #[error("Not allowed: {0}")]
    Forbidden(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("{0}")]
    Other(String),
}

impl From<ClientError> for FfiError {
    fn from(err: ClientError) -> Self {
        if err.is_wrong_pattern() {
            return Self::WrongPattern;
        }
        match err.problem_kind() {
            Some("device-pending") => Self::NotApproved,
            Some("device-not-active") | Some("account-disabled") => Self::DeviceInactive,
            Some("not-found") => Self::NotFound,
            Some("only-admin-can-invite") => Self::Forbidden("only the group admin can invite people".into()),
            Some("only-admin-can-remove") => Self::Forbidden("only the group admin can remove members".into()),
            Some("enrollment-refused") => Self::Forbidden("the invitation code or username was not accepted".into()),
            _ => match err {
                ClientError::Http(e) => Self::Network(e.to_string()),
                ClientError::WebSocket(e) => Self::Network(e.to_string()),
                other => Self::Other(other.to_string()),
            },
        }
    }
}

type FfiResult<T> = Result<T, FfiError>;

fn parse_id(id: &str) -> FfiResult<Uuid> {
    id.parse().map_err(|_| FfiError::Other(format!("invalid id {id}")))
}

fn pattern(dots: Vec<u8>) -> FfiResult<Pattern> {
    Pattern::new(dots).map_err(|e| FfiError::InvalidPattern(format!("{e}.")))
}

fn hardware(secret: Option<Vec<u8>>) -> FfiResult<Option<HardwareSecret>> {
    secret
        .map(|bytes| {
            let bytes = Zeroizing::new(bytes);
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| FfiError::Other("hardware secret must be 32 bytes".into()))
        })
        .transpose()
}

#[derive(uniffi::Record)]
pub struct FfiConversation {
    pub id: String,
    pub title: String,
    pub is_group: bool,
    pub retention_days: u16,
    pub i_am_admin: bool,
    pub members: Vec<String>,
    pub last_seq: i64,
}

#[derive(uniffi::Enum)]
pub enum FfiMessageKind {
    Text,
    Deleted,
    Notice,
    /// This device never received the key (e.g. sent before it was approved).
    Unavailable,
    Undecryptable,
    /// A file; details in [`FfiMessage::media`], `text` holds the caption.
    Media,
}

#[derive(uniffi::Enum)]
pub enum FfiMediaKind {
    Image,
    Video,
    Audio,
    File,
}

/// Describes an attachment. Keys stay inside the Rust session; the app
/// fetches content by message id.
#[derive(uniffi::Record)]
pub struct FfiMedia {
    pub kind: FfiMediaKind,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub has_preview: bool,
}

#[derive(uniffi::Record)]
pub struct FfiMessage {
    pub id: String,
    pub seq: i64,
    pub sender: String,
    pub mine: bool,
    /// RFC 3339.
    pub created_at: String,
    pub kind: FfiMessageKind,
    pub text: String,
    pub media: Option<FfiMedia>,
}

#[derive(uniffi::Record)]
pub struct FfiPage {
    /// Oldest first, ready to display.
    pub messages: Vec<FfiMessage>,
    /// Pass as `before` to load older messages.
    pub next_before: Option<i64>,
}

#[derive(uniffi::Enum)]
pub enum FfiUpdate {
    NewMessage { conversation_id: String },
    MessageDeleted { conversation_id: String, message_id: String },
    ConversationUpdated { conversation_id: String },
}

#[derive(uniffi::Record)]
pub struct FfiHint {
    pub pending_messages: i64,
    pub sender_initial: Option<String>,
}

// One small enum per session behind a mutex; boxing the locked client would
// only add an allocation.
#[allow(clippy::large_enum_variant)]
enum State {
    Locked(LockedClient),
    Unlocked(Box<Client>),
    /// Transient while a blocking unlock runs.
    Busy,
}

#[derive(uniffi::Object)]
pub struct SsmSession {
    state: Mutex<State>,
    /// Media descriptors (with keys) of displayed messages, by message id.
    /// Cleared on lock.
    media: std::sync::Mutex<HashMap<Uuid, MediaInfo>>,
}

impl SsmSession {
    fn new(state: State) -> Arc<Self> {
        Arc::new(SsmSession { state: Mutex::new(state), media: Default::default() })
    }

    fn media_info(&self, message_id: &str) -> FfiResult<MediaInfo> {
        let id = parse_id(message_id)?;
        self.media.lock().expect("media cache poisoned").get(&id).cloned().ok_or(FfiError::NotFound)
    }
}

#[uniffi::export]
pub fn profile_exists(dir: String) -> bool {
    // Checks the files only: opening would take the profile lock, which the
    // app may already hold (UI and push service share one session).
    ssm_client::profile::Profile::at(dir).is_ok_and(|p| p.exists())
}

/// Opens an existing profile in the locked state.
#[uniffi::export]
pub fn open_profile(dir: String) -> FfiResult<Arc<SsmSession>> {
    let locked = LockedClient::open(dir)?;
    Ok(SsmSession::new(State::Locked(locked)))
}

/// Registers this device. `code_or_username` is an invitation code when
/// `with_invite` is true, otherwise the username of an existing account.
#[uniffi::export(async_runtime = "tokio")]
pub async fn enroll(
    dir: String,
    server_url: String,
    code_or_username: String,
    with_invite: bool,
    device_name: String,
    dots: Vec<u8>,
    hardware_secret: Option<Vec<u8>>,
) -> FfiResult<Arc<SsmSession>> {
    let pattern = pattern(dots)?;
    let hardware = hardware(hardware_secret)?;
    trace("enroll: calibrating key derivation");
    let params = tokio::task::spawn_blocking(|| KdfParams::calibrate(KDF_TARGET))
        .await
        .map_err(|e| FfiError::Other(e.to_string()))?
        .map_err(ClientError::from)?;
    trace(&format!("enroll: calibrated ({} MiB, t={}), contacting server", params.m_kib / 1024, params.t));
    let with = if with_invite { EnrollWith::Invite(code_or_username) } else { EnrollWith::Username(code_or_username) };
    let result = Client::enroll(dir, &server_url, with, &device_name, &pattern, params, hardware.as_ref()).await;
    trace(&format!("enroll: finished ({})", if result.is_ok() { "ok" } else { "error" }));
    let client = result?;
    Ok(SsmSession::new(State::Unlocked(Box::new(client))))
}

fn title(conv: &ConversationInfo, me: Option<Uuid>) -> String {
    let others: Vec<&str> = conv
        .members
        .iter()
        .filter(|m| m.status == "active" && Some(m.account_id) != me)
        .map(|m| m.username.as_str())
        .collect();
    match conv.kind {
        ConversationKind::Direct => others.first().copied().unwrap_or("(nobody)").to_owned(),
        ConversationKind::Group if others.is_empty() => "Group (only you)".to_owned(),
        ConversationKind::Group => format!("Group: {}", others.join(", ")),
    }
}

fn name(conv: &ConversationInfo, id: Option<Uuid>) -> String {
    id.and_then(|id| conv.members.iter().find(|m| m.account_id == id).map(|m| m.username.clone()))
        .unwrap_or_else(|| "someone".into())
}

fn notice_text(conv: &ConversationInfo, notice: &SystemNotice) -> String {
    let n = |id: &Uuid| name(conv, Some(*id));
    match notice {
        SystemNotice::ConversationCreated { by } => format!("{} started the conversation", n(by)),
        SystemNotice::MemberAdded { account_id, by } => format!("{} added {}", n(by), n(account_id)),
        SystemNotice::MemberLeft { account_id } => format!("{} left", n(account_id)),
        SystemNotice::MemberRemoved { account_id, by } => format!("{} removed {}", n(by), n(account_id)),
        SystemNotice::RetentionChanged { from_days, to_days, by } => {
            format!("{} changed the retention period from {from_days} to {to_days} days", n(by))
        }
        SystemNotice::AdminChanged { account_id } => format!("{} is now the group admin", n(account_id)),
        SystemNotice::AccountDeleted { username } => {
            format!("The account of {username} was deleted; their messages were removed for everyone")
        }
        SystemNotice::ChatCleared { by } => format!("{} cleared the chat", n(by)),
    }
}

fn to_ffi_conversation(conv: &ConversationInfo, me: Option<Uuid>) -> FfiConversation {
    FfiConversation {
        id: conv.conversation_id.to_string(),
        title: title(conv, me),
        is_group: conv.kind == ConversationKind::Group,
        retention_days: conv.retention_days,
        i_am_admin: conv.members.iter().any(|m| Some(m.account_id) == me && m.status == "active" && m.role == "admin"),
        members: conv.members.iter().filter(|m| m.status == "active").map(|m| m.username.clone()).collect(),
        last_seq: conv.last_seq,
    }
}

impl SsmSession {
    /// Runs `f` with the unlocked client.
    async fn with<T>(&self, f: impl AsyncFnOnce(&mut Client) -> FfiResult<T>) -> FfiResult<T> {
        let mut state = self.state.lock().await;
        match &mut *state {
            State::Unlocked(client) => f(client.as_mut()).await,
            _ => Err(FfiError::Locked),
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SsmSession {
    pub async fn is_unlocked(&self) -> bool {
        matches!(*self.state.lock().await, State::Unlocked(_))
    }

    /// Seconds to wait before the next unlock attempt (after wrong patterns).
    pub async fn unlock_delay_secs(&self) -> u64 {
        match &*self.state.lock().await {
            State::Locked(locked) => locked.unlock_delay().as_secs(),
            _ => 0,
        }
    }

    pub async fn unlock(&self, dots: Vec<u8>, hardware_secret: Option<Vec<u8>>) -> FfiResult<()> {
        let pattern = pattern(dots)?;
        let hardware = hardware(hardware_secret)?;
        let mut state = self.state.lock().await;
        let locked = match std::mem::replace(&mut *state, State::Busy) {
            State::Locked(locked) => locked,
            other => {
                *state = other;
                return Ok(());
            }
        };
        let result = tokio::task::spawn_blocking(move || locked.unlock(&pattern, hardware.as_ref()))
            .await
            .map_err(|e| FfiError::Other(e.to_string()))?;
        match result {
            Ok(client) => {
                *state = State::Unlocked(Box::new(client));
                Ok(())
            }
            Err(failed) => {
                *state = State::Locked(*failed.locked);
                Err(failed.error.into())
            }
        }
    }

    /// Drops keys and decrypted state from memory.
    pub async fn lock(&self) {
        self.media.lock().expect("media cache poisoned").clear();
        let mut state = self.state.lock().await;
        match std::mem::replace(&mut *state, State::Busy) {
            State::Unlocked(client) => *state = State::Locked(client.lock()),
            other => *state = other,
        }
    }

    /// `pending`, `active`, `disabled`, `revoked` or `rejected`.
    pub async fn device_status(&self) -> FfiResult<String> {
        let mut state = self.state.lock().await;
        let status = match &mut *state {
            State::Unlocked(client) => client.device_status().await?,
            State::Locked(locked) => locked.device_status().await?,
            State::Busy => return Err(FfiError::Locked),
        };
        Ok(status.as_str().to_owned())
    }

    pub async fn fingerprint(&self) -> FfiResult<String> {
        self.with(async |c| Ok(c.fingerprint())).await
    }

    pub async fn username(&self) -> Option<String> {
        match &*self.state.lock().await {
            State::Unlocked(client) => client.username().map(str::to_owned),
            State::Locked(locked) => locked.data().username.clone(),
            State::Busy => None,
        }
    }

    /// Registers the push endpoint; `kind` is `unifiedpush` or `fcm`. Works
    /// while locked (push services run without the UI).
    pub async fn set_push_endpoint(&self, kind: String, endpoint: String) -> FfiResult<()> {
        let kind = match kind.as_str() {
            "unifiedpush" => ssm_proto::api::PushKind::UnifiedPush,
            "fcm" => ssm_proto::api::PushKind::Fcm,
            other => return Err(FfiError::Other(format!("unknown push kind {other}"))),
        };
        let state = self.state.lock().await;
        match &*state {
            State::Unlocked(client) => client.set_push_endpoint(kind, &endpoint).await?,
            State::Locked(locked) => locked.set_push_endpoint(kind, &endpoint).await?,
            State::Busy => return Err(FfiError::Locked),
        }
        Ok(())
    }

    /// Works while locked (device key only), for notifications.
    pub async fn notification_hint(&self) -> FfiResult<FfiHint> {
        let state = self.state.lock().await;
        let hint = match &*state {
            State::Unlocked(client) => client.notification_hint().await?,
            State::Locked(locked) => locked.notification_hint().await?,
            State::Busy => return Err(FfiError::Locked),
        };
        Ok(FfiHint { pending_messages: hint.pending_messages, sender_initial: hint.sender_initial })
    }

    pub async fn sync(&self) -> FfiResult<Vec<FfiUpdate>> {
        self.with(async |c| {
            Ok(c.sync()
                .await?
                .into_iter()
                .filter_map(|u| match u {
                    Update::NewMessage { conversation_id, .. } => {
                        Some(FfiUpdate::NewMessage { conversation_id: conversation_id.to_string() })
                    }
                    Update::MessageDeleted { conversation_id, message_id } => Some(FfiUpdate::MessageDeleted {
                        conversation_id: conversation_id.to_string(),
                        message_id: message_id.to_string(),
                    }),
                    Update::ConversationUpdated { conversation_id } => {
                        Some(FfiUpdate::ConversationUpdated { conversation_id: conversation_id.to_string() })
                    }
                    Update::KeyReceived { .. } => None,
                })
                .collect())
        })
        .await
    }

    pub async fn conversations(&self) -> FfiResult<Vec<FfiConversation>> {
        self.with(async |c| {
            let me = c.account_id();
            Ok(c.conversations().await?.iter().map(|conv| to_ffi_conversation(conv, me)).collect())
        })
        .await
    }

    pub async fn conversation(&self, conversation_id: String) -> FfiResult<FfiConversation> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| Ok(to_ffi_conversation(&c.conversation(id).await?, c.account_id()))).await
    }

    /// A page of up to 100 messages, decrypted in memory.
    pub async fn messages(&self, conversation_id: String, before: Option<i64>) -> FfiResult<FfiPage> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| {
            let conv = c.conversation(id).await?;
            let me = c.account_id();
            let (page, next_before) = c.messages(id, before).await?;
            let mut media_cache = self.media.lock().expect("media cache poisoned");
            let messages = page
                .into_iter()
                .rev()
                .map(|m| {
                    let sender = name(&conv, m.sender_account_id);
                    let mut media = None;
                    let (kind, text) = match m.body {
                        DisplayBody::Text(text) => (FfiMessageKind::Text, text),
                        DisplayBody::Media(info) => {
                            media = Some(FfiMedia {
                                kind: match info.kind {
                                    MediaKind::Image => FfiMediaKind::Image,
                                    MediaKind::Video => FfiMediaKind::Video,
                                    MediaKind::Audio => FfiMediaKind::Audio,
                                    MediaKind::File => FfiMediaKind::File,
                                },
                                name: info.name.clone(),
                                mime: info.mime.clone(),
                                size: info.original.size,
                                has_preview: info.preview.is_some(),
                            });
                            let caption = info.caption.clone().unwrap_or_default();
                            media_cache.insert(m.message_id, info);
                            (FfiMessageKind::Media, caption)
                        }
                        DisplayBody::Deleted { by } => {
                            let who = by.map(|id| name(&conv, Some(id))).unwrap_or_else(|| "an administrator".into());
                            (FfiMessageKind::Deleted, format!("Message deleted for everyone by {who}"))
                        }
                        DisplayBody::Notice(notice) => (FfiMessageKind::Notice, notice_text(&conv, &notice)),
                        DisplayBody::Unavailable => {
                            (FfiMessageKind::Unavailable, "This device has no key for this message.".into())
                        }
                        DisplayBody::Undecryptable(reason) => {
                            (FfiMessageKind::Undecryptable, format!("Cannot decrypt: {reason}"))
                        }
                    };
                    FfiMessage {
                        id: m.message_id.to_string(),
                        seq: m.seq,
                        sender,
                        mine: m.sender_account_id.is_some() && m.sender_account_id == me,
                        created_at: m.created_at,
                        kind,
                        text,
                        media,
                    }
                })
                .collect();
            Ok(FfiPage { messages, next_before })
        })
        .await
    }

    pub async fn send_text(&self, conversation_id: String, text: String) -> FfiResult<()> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| {
            c.send_text(id, &text).await?;
            Ok(())
        })
        .await
    }

    /// Encrypts and sends a file. `preview` is a small JPEG for images.
    pub async fn send_media(
        &self,
        conversation_id: String,
        name: String,
        mime: String,
        data: Vec<u8>,
        preview: Option<Vec<u8>>,
        caption: Option<String>,
    ) -> FfiResult<()> {
        let id = parse_id(&conversation_id)?;
        let data = Zeroizing::new(data);
        let preview = preview.map(Zeroizing::new);
        self.with(async |c| {
            c.send_media(id, &name, &mime, &data, preview.as_deref().map(Vec::as_slice), caption.as_deref()).await?;
            Ok(())
        })
        .await
    }

    /// The decrypted preview of a message's attachment (from [`Self::messages`]).
    pub async fn media_preview(&self, message_id: String) -> FfiResult<Vec<u8>> {
        let info = self.media_info(&message_id)?;
        let preview = info.preview.ok_or(FfiError::NotFound)?;
        self.with(async |c| Ok(c.fetch_media(&preview).await?.to_vec())).await
    }

    /// Downloads and decrypts the original (FR-011: only on explicit action).
    pub async fn media_original(&self, message_id: String) -> FfiResult<Vec<u8>> {
        let info = self.media_info(&message_id)?;
        self.with(async |c| Ok(c.fetch_media(&info.original).await?.to_vec())).await
    }

    /// Deletes several messages for everyone; returns how many were deleted.
    pub async fn delete_messages(&self, conversation_id: String, message_ids: Vec<String>) -> FfiResult<i64> {
        let id = parse_id(&conversation_id)?;
        let ids = message_ids.iter().map(|m| parse_id(m)).collect::<FfiResult<Vec<_>>>()?;
        self.with(async |c| Ok(c.delete_messages(id, &ids).await?)).await
    }

    /// Clears the chat for everyone (messages, placeholders, older notices).
    pub async fn clear_chat(&self, conversation_id: String) -> FfiResult<i64> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| Ok(c.clear_chat(id).await?)).await
    }

    /// Deletes every message of the conversation for everyone (also those
    /// not loaded yet); returns how many were deleted.
    pub async fn delete_all_messages(&self, conversation_id: String) -> FfiResult<i64> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| Ok(c.delete_all_messages(id).await?)).await
    }

    /// The only deletion there is: for everyone.
    pub async fn delete_for_all(&self, message_id: String) -> FfiResult<()> {
        let id = parse_id(&message_id)?;
        self.with(async |c| {
            c.delete_for_all(id).await?;
            Ok(())
        })
        .await
    }

    pub async fn set_retention(&self, conversation_id: String, days: u16) -> FfiResult<()> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| {
            c.set_retention(id, days).await?;
            Ok(())
        })
        .await
    }

    /// Direct chat with one username, or a group with several. Returns the
    /// conversation id.
    pub async fn create_chat(&self, usernames: Vec<String>, group: bool) -> FfiResult<String> {
        self.with(async |c| {
            let mut members = Vec::new();
            for name in &usernames {
                members.push(c.lookup(&name.trim().to_lowercase()).await?.account_id);
            }
            let kind = if group { ConversationKind::Group } else { ConversationKind::Direct };
            Ok(c.create_conversation(kind, members, None).await?.conversation_id.to_string())
        })
        .await
    }

    pub async fn add_member(&self, conversation_id: String, username: String) -> FfiResult<()> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| {
            let account = c.lookup(&username.trim().to_lowercase()).await?.account_id;
            c.add_member(id, account).await?;
            Ok(())
        })
        .await
    }

    pub async fn leave(&self, conversation_id: String) -> FfiResult<()> {
        let id = parse_id(&conversation_id)?;
        self.with(async |c| {
            let me = c.account_id().ok_or(FfiError::Other("unknown account".into()))?;
            c.remove_member(id, me).await?;
            Ok(())
        })
        .await
    }
}

/// What [`SsmWatcher::next_wake`] reports.
#[derive(uniffi::Enum)]
pub enum FfiWake {
    /// Something new arrived: ask for [`SsmWatcher::notification_hint`].
    Sync,
    /// The connection ended; call `next_wake` again after a pause.
    Reconnect,
    /// The device was disabled or revoked: stop watching.
    Inactive,
}

/// Keeps a wake-up connection to the server with the device key alone, for
/// the background service (works while the app is locked; never sees
/// content).
#[derive(uniffi::Object)]
pub struct SsmWatcher {
    watcher: ssm_client::Watcher,
    channel: Mutex<Option<ssm_client::WakeChannel>>,
}

#[uniffi::export]
pub fn open_watcher(dir: String) -> FfiResult<Arc<SsmWatcher>> {
    let watcher = ssm_client::Watcher::open(dir)?;
    Ok(Arc::new(SsmWatcher { watcher, channel: Mutex::new(None) }))
}

#[uniffi::export(async_runtime = "tokio")]
impl SsmWatcher {
    /// Waits for the next wake-up, connecting first if needed. Network errors
    /// are returned so the caller can back off.
    pub async fn next_wake(&self) -> FfiResult<FfiWake> {
        let mut slot = self.channel.lock().await;
        if slot.is_none() {
            *slot = Some(self.watcher.connect().await?);
        }
        let channel = slot.as_mut().expect("connected above");
        match channel.next().await {
            ssm_client::Wake::Sync(_) => Ok(FfiWake::Sync),
            ssm_client::Wake::Closed(code) => {
                *slot = None;
                Ok(if code == Some(4003) { FfiWake::Inactive } else { FfiWake::Reconnect })
            }
        }
    }

    pub async fn notification_hint(&self) -> FfiResult<FfiHint> {
        let hint = self.watcher.notification_hint().await?;
        Ok(FfiHint { pending_messages: hint.pending_messages, sender_initial: hint.sender_initial })
    }
}
