-- Phase 1: Olm key distribution and the per-device event stream.

CREATE TABLE one_time_keys (
    device_id   UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    public_key  BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    PRIMARY KEY (device_id, key_id)
);

-- Used when a device has no one-time keys left; replaced on upload.
CREATE TABLE fallback_keys (
    device_id   UUID PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 64),
    public_key  BYTEA NOT NULL CHECK (octet_length(public_key) = 32)
);

-- Per-device sequence. Incrementing it locks the device row, so sequence
-- order equals commit order and a `since` cursor can never skip an event.
ALTER TABLE devices ADD COLUMN event_seq BIGINT NOT NULL DEFAULT 0;

-- Body is the serialized ssm_proto::api::EventBody; never plaintext.
CREATE TABLE events (
    device_id   UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    seq         BIGINT NOT NULL,
    kind        TEXT NOT NULL,
    body        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, seq)
);
CREATE INDEX events_created_idx ON events (created_at);
