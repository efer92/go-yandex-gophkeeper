package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type userRepo struct{ pool *pgxpool.Pool }

func (r *userRepo) Create(ctx context.Context, u storage.User) (storage.User, error) {
	const q = `
		INSERT INTO users (username, email, password_hash, vault_sym_key, kdf_params)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`
	err := r.pool.QueryRow(ctx, q,
		u.Username, u.Email, u.PasswordHash, u.VaultSymKey, u.KDFParams,
	).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return storage.User{}, storage.ErrConflict
		}
		return storage.User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

func (r *userRepo) GetByUsername(ctx context.Context, username string) (storage.User, error) {
	const q = `
		SELECT id, username, email, password_hash, vault_sym_key, kdf_params, mfa_required, created_at
		FROM users WHERE username = $1`
	return r.scanUser(r.pool.QueryRow(ctx, q, username))
}

func (r *userRepo) GetByID(ctx context.Context, id string) (storage.User, error) {
	const q = `
		SELECT id, username, email, password_hash, vault_sym_key, kdf_params, mfa_required, created_at
		FROM users WHERE id = $1`
	return r.scanUser(r.pool.QueryRow(ctx, q, id))
}

func (r *userRepo) SetMFARequired(ctx context.Context, userID string, required bool) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET mfa_required = $1 WHERE id = $2`,
		required, userID)
	return err
}

func (r *userRepo) scanUser(row pgx.Row) (storage.User, error) {
	var u storage.User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash,
		&u.VaultSymKey, &u.KDFParams, &u.MFARequired, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.User{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.User{}, fmt.Errorf("scan user: %w", err)
	}
	return u, nil
}
