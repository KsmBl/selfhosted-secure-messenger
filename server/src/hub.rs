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
}

impl Default for Hub {
    fn default() -> Self {
        Self { sender: broadcast::channel(4096).0 }
    }
}

impl Hub {
    pub fn subscribe(&self) -> broadcast::Receiver<HubEvent> {
        self.sender.subscribe()
    }

    pub fn sync(&self, device_id: Uuid, seq: i64) {
        // No receivers just means nobody is connected.
        let _ = self.sender.send(HubEvent::Sync { device_id, seq });
    }

    pub fn close(&self, device_id: Uuid) {
        let _ = self.sender.send(HubEvent::Close { device_id });
    }
}
