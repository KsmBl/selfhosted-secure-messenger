-- Phase 1: accounts, invites, devices, sessions, admin keys and audit log.

CREATE TABLE accounts (
    id          UUID PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_.-]{3,32}$'),
    role        TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only the SHA-256 of an invite code is stored (ADR-0007).
CREATE TABLE invites (
    id          UUID PRIMARY KEY,
    account_id  UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    code_hash   BYTEA NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id                   UUID PRIMARY KEY,
    account_id           UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    display_name         TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    signing_key          BYTEA NOT NULL UNIQUE CHECK (octet_length(signing_key) = 32),
    olm_identity_key     BYTEA NOT NULL CHECK (octet_length(olm_identity_key) = 32),
    olm_fingerprint_key  BYTEA NOT NULL CHECK (octet_length(olm_fingerprint_key) = 32),
    status               TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'active', 'disabled', 'revoked', 'rejected')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at          TIMESTAMPTZ,
    revoked_at           TIMESTAMPTZ
);
CREATE INDEX devices_account_idx ON devices (account_id);
CREATE INDEX devices_status_idx ON devices (status);

CREATE TABLE admin_keys (
    id          UUID PRIMARY KEY,
    account_id  UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    public_key  BYTEA NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time nonces for proof-of-possession signatures.
CREATE TABLE auth_challenges (
    nonce       BYTEA PRIMARY KEY,
    purpose     TEXT NOT NULL CHECK (purpose IN ('enroll', 'device', 'admin', 'admin_confirm')),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE sessions (
    token_hash  BYTEA PRIMARY KEY,
    device_id   UUID NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_device_idx ON sessions (device_id);

CREATE TABLE admin_sessions (
    token_hash    BYTEA PRIMARY KEY,
    admin_key_id  UUID NOT NULL REFERENCES admin_keys (id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL
);

-- Hash-chained, append-only audit log (TDD §10.4).
CREATE TABLE admin_audit_events (
    id                BIGSERIAL PRIMARY KEY,
    admin_account_id  UUID,
    action            TEXT NOT NULL,
    target            TEXT NOT NULL,
    result            TEXT NOT NULL,
    correlation_id    UUID NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    prev_hash         BYTEA NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash              BYTEA NOT NULL UNIQUE CHECK (octet_length(hash) = 32)
);

CREATE FUNCTION admin_audit_events_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'admin_audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER admin_audit_events_no_update_delete
    BEFORE UPDATE OR DELETE OR TRUNCATE ON admin_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION admin_audit_events_append_only();
