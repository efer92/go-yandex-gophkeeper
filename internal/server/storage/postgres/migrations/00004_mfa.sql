-- +goose Up
CREATE TABLE mfa_totp (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret      TEXT NOT NULL,
    label       TEXT NOT NULL,
    confirmed   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mfa_webauthn (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BYTEA NOT NULL UNIQUE,
    public_key      BYTEA NOT NULL,
    aaguid          BYTEA,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    name            TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Temporary WebAuthn session state (challenge stored server-side)
CREATE TABLE webauthn_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    data        JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes'),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS webauthn_sessions;
DROP TABLE IF EXISTS mfa_webauthn;
DROP TABLE IF EXISTS mfa_totp;
