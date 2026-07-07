-- +goose Up
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    ip          INET,
    user_agent  TEXT,
    result      TEXT NOT NULL CHECK (result IN ('ok','denied','error')),
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS audit_log;
