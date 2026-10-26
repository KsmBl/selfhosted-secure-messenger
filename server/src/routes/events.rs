//! Event stream (`GET /v1/events`) and the WebSocket wake-up channel (`GET /v1/ws`).

use std::time::Duration;

use axum::Json;
use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use ssm_proto::api::{Event, EventsResponse, NotificationHint, WsMessage};
use tokio::sync::broadcast::error::RecvError;

use crate::AppState;
use crate::auth::{self, ActiveDevice, AuthDevice};
use crate::error::{ApiError, ApiResult};
use crate::hub::HubEvent;

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;
const STATUS_RECHECK: Duration = Duration::from_secs(30);
/// Close code: the session ran out; reconnect with a fresh token.
pub const CLOSE_REAUTHENTICATE: u16 = 4001;
/// Close code: the device is no longer active.
pub const CLOSE_DEVICE_INACTIVE: u16 = 4003;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    since: Option<i64>,
    limit: Option<i64>,
}

/// Returns events with `seq > since` and acknowledges (deletes) everything up
/// to `since`, so to-device ciphertexts are removed once delivered.
pub async fn list(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Json<EventsResponse>> {
    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(ApiError::bad_request("since must not be negative"));
    }
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM events WHERE device_id = $1 AND seq <= $2")
        .bind(device.device_id)
        .bind(since)
        .execute(&mut *tx)
        .await?;
    let rows =
        sqlx::query("SELECT seq, created_at, body FROM events WHERE device_id = $1 AND seq > $2 ORDER BY seq LIMIT $3")
            .bind(device.device_id)
            .bind(since)
            .bind(limit + 1)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;

    let more = rows.len() as i64 > limit;
    let events = rows
        .iter()
        .take(limit as usize)
        .map(|row| {
            let body: serde_json::Value = row.try_get("body")?;
            Ok(Event {
                seq: row.try_get("seq")?,
                created_at: row.try_get::<DateTime<Utc>, _>("created_at")?.to_rfc3339(),
                body: serde_json::from_value(body).map_err(|_| ApiError::internal())?,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let next_since = events.last().map_or(since, |e| e.seq);
    Ok(Json(EventsResponse { events, next_since, more }))
}

/// Authenticated with the usual bearer token on the upgrade request.
pub async fn websocket(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| serve(socket, state, device))
}

async fn send(socket: &mut WebSocket, message: &WsMessage) -> bool {
    let text = serde_json::to_string(message).expect("WsMessage serializes");
    socket.send(Message::Text(text.into())).await.is_ok()
}

async fn close(mut socket: WebSocket, code: u16, reason: &'static str) {
    let _ = socket.send(Message::Close(Some(CloseFrame { code, reason: Utf8Bytes::from_static(reason) }))).await;
}

async fn current_seq(state: &AppState, device: &AuthDevice) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT event_seq FROM devices WHERE id = $1")
        .bind(device.device_id)
        .fetch_one(&state.pool)
        .await
}

async fn still_active(state: &AppState, device: &AuthDevice) -> bool {
    let status: Result<Option<String>, _> = sqlx::query_scalar(
        "SELECT d.status FROM devices d JOIN accounts a ON a.id = d.account_id
         WHERE d.id = $1 AND a.status = 'active'",
    )
    .bind(device.device_id)
    .fetch_optional(&state.pool)
    .await;
    matches!(status, Ok(Some(s)) if s == "active")
}

/// Sends `sync` hints for this device until the session lifetime is over, the
/// device is deactivated or the client disconnects. Client frames are ignored.
async fn serve(mut socket: WebSocket, state: AppState, device: AuthDevice) {
    let hub_handle = state.hub.clone();
    let _connected = hub_handle.connection(device.device_id);
    let mut hub = state.hub.subscribe();
    let deadline = tokio::time::sleep(auth::DEVICE_SESSION_TTL.to_std().expect("positive TTL"));
    tokio::pin!(deadline);
    let mut recheck = tokio::time::interval(STATUS_RECHECK);
    recheck.tick().await;

    // Tell the client where the stream stands right after connecting.
    let Ok(seq) = current_seq(&state, &device).await else { return };
    if !send(&mut socket, &WsMessage::Sync { seq }).await {
        return;
    }

    loop {
        tokio::select! {
            event = hub.recv() => match event {
                Ok(HubEvent::Sync { device_id, seq }) if device_id == device.device_id => {
                    if !send(&mut socket, &WsMessage::Sync { seq }).await {
                        return;
                    }
                }
                Ok(HubEvent::Close { device_id }) if device_id == device.device_id => {
                    return close(socket, CLOSE_DEVICE_INACTIVE, "device not active").await;
                }
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => {
                    let Ok(seq) = current_seq(&state, &device).await else { return };
                    if !send(&mut socket, &WsMessage::Sync { seq }).await {
                        return;
                    }
                }
                Err(RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            },
            _ = recheck.tick() => {
                if !still_active(&state, &device).await {
                    return close(socket, CLOSE_DEVICE_INACTIVE, "device not active").await;
                }
            }
            _ = &mut deadline => {
                return close(socket, CLOSE_REAUTHENTICATE, "session expired").await;
            }
        }
    }
}

/// What a woken-up device may show while locked (ADR-0008): the number of
/// pending messages and the first letter of the latest sender's username.
pub async fn notification_hint(
    State(state): State<AppState>,
    ActiveDevice(device): ActiveDevice,
) -> ApiResult<Json<NotificationHint>> {
    let pending_messages: i64 =
        sqlx::query_scalar("SELECT count(*) FROM events WHERE device_id = $1 AND kind = 'message'")
            .bind(device.device_id)
            .fetch_one(&state.pool)
            .await?;
    let latest_sender: Option<String> = sqlx::query_scalar(
        "SELECT a.username FROM events e
         JOIN messages m ON m.conversation_id = (e.body->'payload'->>'conversation_id')::uuid
                        AND m.seq = (e.body->'payload'->>'seq')::bigint
         JOIN accounts a ON a.id = m.sender_account_id
         WHERE e.device_id = $1 AND e.kind = 'message' AND m.deleted_at IS NULL AND m.expires_at > now()
         ORDER BY e.seq DESC LIMIT 1",
    )
    .bind(device.device_id)
    .fetch_optional(&state.pool)
    .await?;
    let sender_initial = latest_sender.and_then(|name| name.chars().next()).map(|c| c.to_uppercase().to_string());
    Ok(Json(NotificationHint { pending_messages, sender_initial }))
}
