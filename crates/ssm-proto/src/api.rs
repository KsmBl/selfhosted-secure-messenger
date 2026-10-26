//! Request and response bodies of the v1 API. Timestamps are RFC 3339 strings.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::B64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Pending,
    Active,
    Disabled,
    Revoked,
    Rejected,
}

impl DeviceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pending" => Self::Pending,
            "active" => Self::Active,
            "disabled" => Self::Disabled,
            "revoked" => Self::Revoked,
            "rejected" => Self::Rejected,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub nonce: B64,
    pub expires_in_secs: u64,
}

/// Exactly one of `invite_code` (first device) or `username` (further devices).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub invite_code: Option<String>,
    pub username: Option<String>,
    pub display_name: String,
    pub signing_key: B64,
    pub olm_identity_key: B64,
    pub olm_fingerprint_key: B64,
    pub nonce: B64,
    pub signature: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub device_id: Uuid,
    pub nonce: B64,
    pub signature: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatusResponse {
    pub device_id: Uuid,
    pub status: DeviceStatus,
    pub account_id: Uuid,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: Uuid,
    pub display_name: String,
    pub status: DeviceStatus,
    pub olm_fingerprint_key: B64,
    pub created_at: String,
}

// ---- Admin API ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSessionRequest {
    pub admin_key_id: Uuid,
    pub nonce: B64,
    pub signature: B64,
}

/// Fresh signature over `admin_confirm_message` for destructive actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRequest {
    pub nonce: B64,
    pub signature: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteResponse {
    pub account_id: Uuid,
    pub invite_code: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account_id: Uuid,
    pub username: String,
    pub role: String,
    pub status: String,
    pub created_at: String,
    #[serde(default)]
    pub active_devices: i64,
    /// Messages the account sent that still have content.
    #[serde(default)]
    pub messages: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminDeviceInfo {
    pub device_id: Uuid,
    pub account_id: Uuid,
    pub username: String,
    pub display_name: String,
    pub status: DeviceStatus,
    pub olm_fingerprint_key: B64,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceAction {
    Approve,
    Reject,
    Disable,
    Enable,
    Revoke,
}

impl DeviceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::Revoke => "revoke",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "approve" => Self::Approve,
            "reject" => Self::Reject,
            "disable" => Self::Disable,
            "enable" => Self::Enable,
            "revoke" => Self::Revoke,
            _ => return None,
        })
    }

    /// Actions that need a fresh confirmation signature (ADR-0006).
    pub fn is_destructive(self) -> bool {
        matches!(self, Self::Revoke)
    }

    /// Allowed status transitions (ADR-0003).
    pub fn transition(self, from: DeviceStatus) -> Option<DeviceStatus> {
        use DeviceStatus::*;
        match (self, from) {
            (Self::Approve, Pending) => Some(Active),
            (Self::Reject, Pending) => Some(Rejected),
            (Self::Disable, Active) => Some(Disabled),
            (Self::Enable, Disabled) => Some(Active),
            (Self::Revoke, Active | Disabled) => Some(Revoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    pub admin_account_id: Option<Uuid>,
    pub action: String,
    pub target: String,
    pub result: String,
    pub correlation_id: Uuid,
    pub created_at: String,
    pub hash: String,
    /// Target with names instead of ids, e.g. "account alice".
    #[serde(default)]
    pub target_label: String,
}

/// RFC 9457 problem details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ---- Olm key distribution ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeKey {
    pub key_id: String,
    pub public_key: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadKeysRequest {
    #[serde(default)]
    pub one_time_keys: Vec<OneTimeKey>,
    /// Replaces the previous fallback key; used once one-time keys run out.
    pub fallback_key: Option<OneTimeKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadKeysResponse {
    pub one_time_key_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimKeysRequest {
    pub device_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedKey {
    pub device_id: Uuid,
    pub key_id: String,
    pub public_key: B64,
    pub fallback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimKeysResponse {
    pub keys: Vec<ClaimedKey>,
    /// Devices that are not active or have no key left.
    pub unavailable: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLookup {
    pub account_id: Uuid,
    pub username: String,
}

/// An active device of some account, as needed to establish Olm sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDevice {
    pub device_id: Uuid,
    pub display_name: String,
    pub olm_identity_key: B64,
    pub olm_fingerprint_key: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDeviceMessage {
    pub device_id: Uuid,
    /// Olm message type: 0 = pre-key, 1 = normal.
    pub message_type: u8,
    pub ciphertext: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendToDeviceRequest {
    pub messages: Vec<ToDeviceMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendToDeviceResponse {
    pub delivered: u32,
    /// Target devices that are unknown or not active.
    pub skipped: Vec<Uuid>,
}

// ---- Events and real-time channel ----

/// Per-device event. Never contains plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum EventBody {
    ToDevice {
        sender_device_id: Uuid,
        sender_identity_key: B64,
        message_type: u8,
        ciphertext: B64,
    },
    /// A new message (including system notices) in a conversation.
    Message {
        conversation_id: Uuid,
        seq: i64,
    },
    /// A message was deleted for everyone; drop it from memory and caches.
    MessageDeleted {
        conversation_id: Uuid,
        message_id: Uuid,
    },
    /// Members or retention changed; re-fetch the conversation.
    ConversationUpdated {
        conversation_id: Uuid,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: i64,
    pub created_at: String,
    #[serde(flatten)]
    pub body: EventBody,
}

/// `GET /v1/events?since=N`: events with `seq > N`. Passing `since` also
/// acknowledges (deletes) all events up to `N`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<Event>,
    pub next_since: i64,
    pub more: bool,
}

/// Server → client WebSocket frames. The channel only wakes the client up;
/// data is always fetched through `GET /v1/events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    Sync { seq: i64 },
}

// ---- Conversations and messages ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversationKind {
    Direct,
    Group,
}

impl ConversationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Group => "group",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "direct" => Some(Self::Direct),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

pub const DEFAULT_RETENTION_DAYS: u16 = 90;
pub const MIN_RETENTION_DAYS: u16 = 1;
pub const MAX_RETENTION_DAYS: u16 = 365;
pub const PAGE_SIZE: i64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateConversationRequest {
    pub kind: ConversationKind,
    /// Other members; the caller is added automatically.
    pub members: Vec<Uuid>,
    pub retention_days: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberInfo {
    pub account_id: Uuid,
    pub username: String,
    pub status: String,
    /// `admin` (may invite and remove members) or `member`.
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationInfo {
    pub conversation_id: Uuid,
    pub kind: ConversationKind,
    pub retention_days: u16,
    /// `None` once the creator's account was deleted.
    pub created_by: Option<Uuid>,
    pub created_at: String,
    pub last_seq: i64,
    pub members: Vec<MemberInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub account_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionRequest {
    pub days: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Idempotency key chosen by the sending device.
    pub client_id: Uuid,
    pub session_id: String,
    pub ciphertext: B64,
    /// Media objects uploaded for this message (same conversation, same
    /// device); they are deleted together with the message.
    #[serde(default)]
    pub media_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub message_id: Uuid,
    pub seq: i64,
    pub created_at: String,
    pub expires_at: String,
}

/// Server-generated timeline notices. Metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "notice", rename_all = "snake_case")]
pub enum SystemNotice {
    ConversationCreated {
        by: Uuid,
    },
    MemberAdded {
        account_id: Uuid,
        by: Uuid,
    },
    MemberLeft {
        account_id: Uuid,
    },
    MemberRemoved {
        account_id: Uuid,
        by: Uuid,
    },
    RetentionChanged {
        from_days: u16,
        to_days: u16,
        by: Uuid,
    },
    /// The previous group admin left; this member is the new admin.
    AdminChanged {
        account_id: Uuid,
    },
    /// The account was deleted by the server administrator; its messages
    /// were deleted for everyone. Carries the name because the account is gone.
    AccountDeleted {
        username: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessageBody {
    Encrypted {
        session_id: String,
        ciphertext: B64,
    },
    /// Tombstone: the content is gone for everyone.
    Deleted {
        deleted_by: Option<Uuid>,
        deleted_at: String,
    },
    System {
        notice: SystemNotice,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageItem {
    pub message_id: Uuid,
    pub seq: i64,
    pub sender_account_id: Option<Uuid>,
    pub sender_device_id: Option<Uuid>,
    pub created_at: String,
    pub expires_at: String,
    #[serde(flatten)]
    pub body: MessageBody,
}

/// Newest first. Pass `next_before` as `before` to load the next older page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesPage {
    pub messages: Vec<MessageItem>,
    pub next_before: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    /// Idempotency key: repeating it returns the same job.
    pub operation_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteJobStatus {
    Requested,
    InProgress,
    ActiveRemoved,
    BackupPurgePending,
    BackupPurgeDone,
    Failed,
}

impl DeleteJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::InProgress => "in_progress",
            Self::ActiveRemoved => "active_removed",
            Self::BackupPurgePending => "backup_purge_pending",
            Self::BackupPurgeDone => "backup_purge_done",
            Self::Failed => "failed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "requested" => Self::Requested,
            "in_progress" => Self::InProgress,
            "active_removed" => Self::ActiveRemoved,
            "backup_purge_pending" => Self::BackupPurgePending,
            "backup_purge_done" => Self::BackupPurgeDone,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteJobInfo {
    pub job_id: Uuid,
    pub operation_id: Uuid,
    pub status: DeleteJobStatus,
    pub affected_messages: i64,
    pub created_at: String,
    pub updated_at: String,
    /// When backups no longer contain the deleted data.
    pub backup_purge_due_at: Option<String>,
    pub error_summary: Option<String>,
}

// ---- Admin mass deletion (FR-018) ----

/// Shown before confirming a mass deletion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSummary {
    pub account_id: Uuid,
    pub username: String,
    /// Messages sent by the account that still have content.
    pub messages: i64,
    pub conversations: i64,
}

/// Confirmation signature over `admin_confirm_message(nonce,
/// "delete-all-content", "account:<id>")`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MassDeleteRequest {
    pub operation_id: Uuid,
    pub nonce: B64,
    pub signature: B64,
}

// ---- Notifications (ADR-0008) ----

/// Fetched after a push wake-up. Only the first letter of the sender's
/// username is ever revealed for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationHint {
    pub pending_messages: i64,
    pub sender_initial: Option<String>,
}

/// `DELETE /v1/devices/self`: the device removed itself (signed out for good).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRemoved {
    pub device_id: Uuid,
}

// ---- Admin client support ----

/// Unauthenticated: which admin key id belongs to this public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyLookup {
    pub admin_key_id: Uuid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminOverview {
    pub accounts: i64,
    pub admins: i64,
    pub devices_pending: i64,
    pub devices_active: i64,
    pub devices_disabled: i64,
    pub conversations: i64,
    pub messages: i64,
    pub jobs_running: i64,
    pub jobs_backup_pending: i64,
    pub audit_entries: i64,
    /// `None` if intact, otherwise the first entry that does not match.
    pub audit_broken_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminJob {
    pub job_id: Uuid,
    /// Human-readable scope, e.g. "all content of alice".
    pub scope: String,
    pub status: DeleteJobStatus,
    pub affected_messages: i64,
    pub created_at: String,
    pub backup_purge_due_at: Option<String>,
    pub error_summary: Option<String>,
}

/// Lock (`disabled: true`) or unlock an account; needs a confirmation for
/// action `disable-account` / `enable-account` and target `account:<id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatusRequest {
    pub disabled: bool,
    pub confirm: ConfirmRequest,
}

/// Grant or remove the admin role; action `grant-admin` / `revoke-admin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRoleRequest {
    pub admin: bool,
    pub confirm: ConfirmRequest,
}

/// Register an admin public key; action `add-admin-key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddAdminKeyRequest {
    pub public_key: B64,
    pub confirm: ConfirmRequest,
}

/// Result text of a management operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminOutcome {
    pub message: String,
}

// ---- Push (ADR-0008) ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushKind {
    /// HTTPS endpoint of a UnifiedPush distributor (e.g. ntfy).
    UnifiedPush,
    /// Firebase Cloud Messaging registration token (fallback).
    Fcm,
}

impl PushKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnifiedPush => "unifiedpush",
            Self::Fcm => "fcm",
        }
    }
}

/// `PUT /v1/push-endpoint`: where to send content-free wake-ups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushEndpointRequest {
    pub kind: PushKind,
    pub endpoint: String,
}

// ---- Media (FR-011) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaUploaded {
    pub media_id: Uuid,
}
