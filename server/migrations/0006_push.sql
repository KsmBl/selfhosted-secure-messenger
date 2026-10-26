-- Push wake-ups (ADR-0008): one endpoint per device (UnifiedPush URL or FCM
-- registration token). The payload sent there never carries content.
CREATE TABLE push_endpoints (
    device_id   UUID PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('unifiedpush', 'fcm')),
    endpoint    TEXT NOT NULL CHECK (char_length(endpoint) BETWEEN 1 AND 2048),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
