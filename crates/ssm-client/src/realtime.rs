//! WebSocket wake-up channel (ADR-0008). The server only sends `sync` hints;
//! react to them by calling [`crate::Client::sync`].

use futures_util::StreamExt;
use ssm_proto::api::WsMessage;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::error::{ClientError, ClientResult};

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

    /// Next wake-up; `Closed` once the connection is gone.
    pub async fn next(&mut self) -> Wake {
        loop {
            match self.socket.next().await {
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
