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
    ToDevice { sender_device_id: Uuid, sender_identity_key: B64, message_type: u8, ciphertext: B64 },
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
