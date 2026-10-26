-- Phases 3/4: conversations, messages, global deletion and retention.

CREATE TABLE conversations (
    id              UUID PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('direct', 'group')),
    retention_days  INT NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 1 AND 365),
    created_by      UUID NOT NULL REFERENCES accounts (id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Incrementing locks the conversation row: message order = commit order.
    message_seq     BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE conversation_members (
    conversation_id  UUID NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    account_id       UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'left', 'removed')),
    joined_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Messages with seq <= joined_seq predate this membership and stay hidden.
    joined_seq       BIGINT NOT NULL DEFAULT 0,
    left_at          TIMESTAMPTZ,
    PRIMARY KEY (conversation_id, account_id)
);
CREATE INDEX conversation_members_account_idx ON conversation_members (account_id) WHERE status = 'active';

CREATE TABLE delete_jobs (
    id                    UUID PRIMARY KEY,
    operation_id          UUID NOT NULL,
    requested_by          UUID REFERENCES accounts (id) ON DELETE SET NULL,
    requested_by_admin    BOOLEAN NOT NULL DEFAULT false,
    scope                 JSONB NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('requested', 'in_progress', 'active_removed',
                              'backup_purge_pending', 'backup_purge_done', 'failed')),
    affected_messages     BIGINT NOT NULL DEFAULT 0,
    error_summary         TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    backup_purge_due_at   TIMESTAMPTZ,
    completed_at          TIMESTAMPTZ,
    UNIQUE (requested_by, operation_id)
);
CREATE INDEX delete_jobs_backup_idx ON delete_jobs (backup_purge_due_at) WHERE status = 'backup_purge_pending';

-- kind = 'encrypted': session_id + ciphertext (Megolm), NULL once deleted.
-- kind = 'system': server-generated notice (metadata only, never user content).
CREATE TABLE messages (
    id                 UUID PRIMARY KEY,
    conversation_id    UUID NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    seq                BIGINT NOT NULL,
    kind               TEXT NOT NULL CHECK (kind IN ('encrypted', 'system')),
    sender_account_id  UUID REFERENCES accounts (id) ON DELETE SET NULL,
    sender_device_id   UUID REFERENCES devices (id) ON DELETE SET NULL,
    client_id          UUID,
    session_id         TEXT,
    ciphertext         BYTEA,
    notice             JSONB,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    deleted_at         TIMESTAMPTZ,
    deleted_by         UUID REFERENCES accounts (id) ON DELETE SET NULL,
    delete_job_id      UUID REFERENCES delete_jobs (id) ON DELETE SET NULL,
    UNIQUE (conversation_id, seq),
    UNIQUE (sender_device_id, client_id),
    CHECK (kind <> 'system' OR notice IS NOT NULL),
    CHECK (deleted_at IS NULL OR (ciphertext IS NULL AND session_id IS NULL))
);
CREATE INDEX messages_expiry_idx ON messages (expires_at);
CREATE INDEX messages_sender_idx ON messages (sender_account_id) WHERE deleted_at IS NULL;
