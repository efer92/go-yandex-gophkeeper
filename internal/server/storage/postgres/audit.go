package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type auditRepo struct{ pool *pgxpool.Pool }

func (r *auditRepo) Append(ctx context.Context, e storage.AuditEntry) error {
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		detail = []byte("{}")
	}
	var userID *string
	if e.UserID != "" {
		userID = &e.UserID
	}
	_, err = r.pool.Exec(ctx,
		`INSERT INTO audit_log (user_id, action, ip, user_agent, result, detail, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, e.Action, e.IP, e.UserAgent, e.Result, detail, e.CreatedAt)
	if err != nil {
		return fmt.Errorf("audit append: %w", err)
	}
	return nil
}
