use ssm_core::e2ee::E2eeError;
use ssm_core::{ContainerError, PatternError};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The server answered with a problem document.
    #[error("server error {status} ({kind}){}", detail.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    Api { status: u16, kind: String, detail: Option<String> },
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("encryption error: {0}")]
    Crypto(#[from] E2eeError),
    #[error("key container: {0}")]
    Container(#[from] ContainerError),
    #[error("invalid pattern: {0}")]
    Pattern(#[from] PatternError),
    #[error("profile storage: {0}")]
    Io(#[from] std::io::Error),
    #[error("profile is corrupt: {0}")]
    Profile(String),
    #[error("unexpected server response: {0}")]
    Protocol(String),
}

impl ClientError {
    /// Problem kind (e.g. `device-pending`) for API errors.
    pub fn problem_kind(&self) -> Option<&str> {
        match self {
            Self::Api { kind, .. } => Some(kind),
            _ => None,
        }
    }

    pub fn is_wrong_pattern(&self) -> bool {
        matches!(self, Self::Container(ContainerError::Unlock))
    }
}

pub type ClientResult<T> = Result<T, ClientError>;
