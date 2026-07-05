-- +goose Up
CREATE TABLE vault_items (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN ('credential','text','binary','card','otp')),
    payload     BYTEA NOT NULL,
    metadata    TEXT,
    version     BIGINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vault_user_updated ON vault_items(user_id, updated_at DESC);

-- +goose Down
DROP TABLE IF EXISTS vault_items;
