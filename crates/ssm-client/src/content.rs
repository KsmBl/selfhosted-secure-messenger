//! Message content inside the Megolm envelope, and what the UI displays.

use serde::{Deserialize, Serialize};
use ssm_proto::api::SystemNotice;
use uuid::Uuid;

/// Plaintext message content. Only ever exists in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    Text {
        text: String,
    },
    /// An encrypted file; keys are only inside this (E2E-encrypted) content.
    Media(MediaInfo),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MediaKind {
    Image,
    Video,
    Audio,
    File,
}

impl MediaKind {
    pub fn from_mime(mime: &str) -> Self {
        match mime.split('/').next() {
            Some("image") => Self::Image,
            Some("video") => Self::Video,
            Some("audio") => Self::Audio,
            _ => Self::File,
        }
    }
}

/// Where an encrypted object is and how to decrypt it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaRef {
    pub media_id: Uuid,
    pub key: ssm_proto::B64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaInfo {
    pub kind: MediaKind,
    pub name: String,
    pub mime: String,
    /// Original, downloaded only on explicit action (FR-011).
    pub original: MediaRef,
    /// Small separately encrypted preview (images).
    pub preview: Option<MediaRef>,
    #[serde(default)]
    pub caption: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayBody {
    Text(String),
    Media(MediaInfo),
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
