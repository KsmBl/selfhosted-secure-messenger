//! Message content inside the Megolm envelope, and what the UI displays.

use serde::{Deserialize, Serialize};
use ssm_proto::api::SystemNotice;
use uuid::Uuid;

/// Plaintext message content. Only ever exists in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    Text { text: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayBody {
    Text(String),
    /// The key never reached this device (e.g. sent before it was approved).
    Unavailable,
    /// Decryption or format error.
    Undecryptable(String),
    Deleted {
        by: Option<Uuid>,
    },
    Notice(SystemNotice),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayMessage {
    pub message_id: Uuid,
    pub seq: i64,
    pub sender_account_id: Option<Uuid>,
    pub sender_device_id: Option<Uuid>,
    pub created_at: String,
    pub expires_at: String,
    pub body: DisplayBody,
}
