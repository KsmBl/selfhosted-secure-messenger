//! WebSocket wake-up channel (ADR-0008). The server only sends `sync` hints;
//! react to them by calling [`crate::Client::sync`]. While the app is locked,
//! a [`Watcher`] keeps the channel open with the device key alone and asks
//! for the content-free notification hint.

use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use ssm_proto::api::WsMessage;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::api::Api;
use crate::error::{ClientError, ClientResult};
use crate::profile::Profile;

/// The server pings every 30 s; silence for this long means the connection
/// is dead (suspend, network change) and must be re-established.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wake {
    /// New events up to this sequence are waiting.
    Sync(i64),
    /// The server closed the channel. 4001: session expired (reconnect with a
    /// new token), 4003: device no longer active.
    Closed(Option<u16>),
}

pub struct WakeChannel {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WakeChannel {
    /// `url` and `token` come from [`crate::Client::realtime_credentials`], so
    /// the client does not need to stay borrowed while listening.
    pub async fn connect(url: &str, token: &str) -> ClientResult<Self> {
        let mut request = url.into_client_request()?;
        let header = format!("Bearer {token}").parse().map_err(|_| ClientError::Protocol("token".into()))?;
        request.headers_mut().insert("authorization", header);
        let (socket, _) = tokio_tungstenite::connect_async(request).await?;
        Ok(Self { socket })
    }

    /// Next wake-up; `Closed` once the connection is gone or silent too long.
    pub async fn next(&mut self) -> Wake {
        loop {
            let Ok(frame) = tokio::time::timeout(IDLE_TIMEOUT, self.socket.next()).await else {
                return Wake::Closed(None);
            };
            match frame {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(WsMessage::Sync { seq }) = serde_json::from_str(&text) {
                        return Wake::Sync(seq);
                    }
                }
                Some(Ok(Message::Close(frame))) => return Wake::Closed(frame.map(|f| f.code.into())),
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Wake::Closed(None),
            }
        }
    }
}

/// Listens for new messages while the profile is locked. Needs only the
/// device key (stored outside the key container) and never sees content:
/// the server answers with the number of waiting messages and the first
/// letter of the latest sender.
pub struct Watcher {
    api: Api,
}

impl Watcher {
    /// Reads the profile without taking its lock, so it can run next to the
    /// locked or unlocked client of the same profile.
    pub fn open(dir: impl AsRef<Path>) -> ClientResult<Self> {
        let profile = Profile::at(dir.as_ref())?;
        let data = profile.load()?;
        Ok(Self { api: Api::new(&data.server_url, profile.load_device_key()?, data.device_id)? })
    }

    /// Opens a wake-up channel with a fresh session token.
    pub async fn connect(&self) -> ClientResult<WakeChannel> {
        let token = self.api.token().await?;
        WakeChannel::connect(&self.api.websocket_url(), &token).await
    }

    pub async fn notification_hint(&self) -> ClientResult<ssm_proto::api::NotificationHint> {
        self.api.get("/v1/notifications/hint").await
    }
}
