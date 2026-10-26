-- Encrypted media objects (FR-009, FR-011). The server stores only
-- nonce || ciphertext in files under the media directory; keys travel in the
-- E2E-encrypted message. Objects are linked to their message when it is sent.
CREATE TABLE media_objects (
    id                  UUID PRIMARY KEY,
    conversation_id     UUID NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    uploader_device_id  UUID NOT NULL,
    message_id          UUID REFERENCES messages (id) ON DELETE SET NULL,
    size                BIGINT NOT NULL,
    purge               BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX media_objects_message_idx ON media_objects (message_id);
CREATE INDEX media_objects_purge_idx ON media_objects (purge) WHERE purge;
