//! In-process fan-out of wake-up signals to connected WebSockets.
//!
//! Only signals travel through the hub; clients always fetch data through
//! `GET /v1/events`. A single server process is assumed (self-hosted).

use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum HubEvent {
    Sync { device_id: Uuid, seq: i64 },
    Close { device_id: Uuid },
}

pub struct Hub {
    sender: broadcast::Sender<HubEvent>,
    /// Open WebSocket connections per device.
    connected: std::sync::Mutex<std::collections::HashMap<Uuid, usize>>,
    /// Wake-ups for devices without an open connection.
    push: std::sync::OnceLock<crate::push::Pusher>,
}

impl Default for Hub {
    fn default() -> Self {
        Self { sender: broadcast::channel(4096).0, connected: Default::default(), push: std::sync::OnceLock::new() }
    }
}

/// Keeps a device marked as connected while alive.
pub struct ConnectionGuard<'a> {
    hub: &'a Hub,
    device_id: Uuid,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        let mut connected = self.hub.connected.lock().unwrap();
        if let Some(count) = connected.get_mut(&self.device_id) {
            *count -= 1;
            if *count == 0 {
                connected.remove(&self.device_id);
            }
        }
    }
}

impl Hub {
    pub fn subscribe(&self) -> broadcast::Receiver<HubEvent> {
        self.sender.subscribe()
    }

    pub fn set_pusher(&self, pusher: crate::push::Pusher) {
        let _ = self.push.set(pusher);
    }

    pub fn connection(&self, device_id: Uuid) -> ConnectionGuard<'_> {
        *self.connected.lock().unwrap().entry(device_id).or_default() += 1;
        ConnectionGuard { hub: self, device_id }
    }

    pub fn is_connected(&self, device_id: Uuid) -> bool {
        self.connected.lock().unwrap().contains_key(&device_id)
    }

    /// Wakes the device: over its WebSocket if connected, otherwise by push.
    pub fn sync(&self, device_id: Uuid, seq: i64) {
        // No receivers just means nobody is connected.
        let _ = self.sender.send(HubEvent::Sync { device_id, seq });
        if !self.is_connected(device_id)
            && let Some(pusher) = self.push.get()
        {
            pusher.wake(device_id);
        }
    }

    pub fn close(&self, device_id: Uuid) {
        let _ = self.sender.send(HubEvent::Close { device_id });
    }
}

/// PostgreSQL channel that carries hub events from other processes (TUI,
/// `ssm-admin`) to the running server.
pub const PG_CHANNEL: &str = "ssm_hub";

fn encode(event: HubEvent) -> String {
    match event {
        HubEvent::Sync { device_id, seq } => format!("sync {device_id} {seq}"),
        HubEvent::Close { device_id } => format!("close {device_id}"),
    }
}

fn decode(payload: &str) -> Option<HubEvent> {
    let mut parts = payload.split(' ');
    match (parts.next()?, parts.next()?.parse().ok()?, parts.next()) {
        ("sync", device_id, Some(seq)) => Some(HubEvent::Sync { device_id, seq: seq.parse().ok()? }),
        ("close", device_id, None) => Some(HubEvent::Close { device_id }),
        _ => None,
    }
}

/// Sends events to the server process through `pg_notify`.
pub async fn publish(pool: &sqlx::PgPool, events: &[HubEvent]) -> sqlx::Result<()> {
    for event in events {
        sqlx::query("SELECT pg_notify($1, $2)").bind(PG_CHANNEL).bind(encode(*event)).execute(pool).await?;
    }
    Ok(())
}

/// Server side: forwards events published by other processes into `hub`.
pub fn spawn_listener(pool: sqlx::PgPool, hub: std::sync::Arc<Hub>) {
    tokio::spawn(async move {
        loop {
            let result = async {
                let mut listener = sqlx::postgres::PgListener::connect_with(&pool).await?;
                listener.listen(PG_CHANNEL).await?;
                loop {
                    let notification = listener.recv().await?;
                    match decode(notification.payload()) {
                        Some(HubEvent::Sync { device_id, seq }) => hub.sync(device_id, seq),
                        Some(HubEvent::Close { device_id }) => hub.close(device_id),
                        None => tracing::warn!(payload = notification.payload(), "ignoring malformed hub event"),
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), sqlx::Error>(())
            }
            .await;
            if let Err(err) = result {
                tracing::warn!(error = %err, "hub listener failed, retrying");
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_roundtrip_through_payload() {
        let id = Uuid::new_v4();
        for event in [HubEvent::Sync { device_id: id, seq: 42 }, HubEvent::Close { device_id: id }] {
            let back = decode(&encode(event)).unwrap();
            assert_eq!(format!("{back:?}"), format!("{event:?}"));
        }
        assert!(decode("sync nonsense 1").is_none());
        assert!(decode("close").is_none());
    }
}
