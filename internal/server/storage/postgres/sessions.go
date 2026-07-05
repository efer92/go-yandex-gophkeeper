package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sessionRepo struct{ pool *pgxpool.Pool }

func (r *sessionRepo) Create(ctx context.Context, s storage.Session) (storage.Session, error) {
	const q = `
		INSERT INTO sessions (user_id, refresh_token, expires_at, mfa_verified)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`
	err := r.pool.QueryRow(ctx, q, s.UserID, s.RefreshToken, s.ExpiresAt, s.MFAVerified).
		Scan(&s.ID, &s.CreatedAt)
	if err != nil {
		return storage.Session{}, fmt.Errorf("create session: %w", err)
	}
	return s, nil
}

func (r *sessionRepo) GetByRefreshToken(ctx context.Context, token string) (storage.Session, error) {
	const q = `
		SELECT id, user_id, refresh_token, expires_at, mfa_verified, created_at
		FROM sessions WHERE refresh_token = $1`
	var s storage.Session
	err := r.pool.QueryRow(ctx, q, token).Scan(
		&s.ID, &s.UserID, &s.RefreshToken, &s.ExpiresAt, &s.MFAVerified, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.Session{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Session{}, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

func (r *sessionRepo) SetMFAVerified(ctx context.Context, sessionID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE sessions SET mfa_verified = TRUE WHERE id = $1`, sessionID)
	return err
}

func (r *sessionRepo) Delete(ctx context.Context, refreshToken string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM sessions WHERE refresh_token = $1`, refreshToken)
	return err
}

func (r *sessionRepo) DeleteExpired(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	return err
}
