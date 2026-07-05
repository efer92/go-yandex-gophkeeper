package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type mfaRepo struct{ pool *pgxpool.Pool }

func (r *mfaRepo) CreateTOTP(ctx context.Context, rec storage.TOTPRecord) (storage.TOTPRecord, error) {
	const q = `
		INSERT INTO mfa_totp (user_id, secret, label)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`
	err := r.pool.QueryRow(ctx, q, rec.UserID, rec.Secret, rec.Label).
		Scan(&rec.ID, &rec.CreatedAt)
	if err != nil {
		return storage.TOTPRecord{}, fmt.Errorf("create totp: %w", err)
	}
	return rec, nil
}

func (r *mfaRepo) GetTOTPByID(ctx context.Context, id, userID string) (storage.TOTPRecord, error) {
	const q = `
		SELECT id, user_id, secret, label, confirmed, created_at
		FROM mfa_totp WHERE id = $1 AND user_id = $2`
	var rec storage.TOTPRecord
	err := r.pool.QueryRow(ctx, q, id, userID).
		Scan(&rec.ID, &rec.UserID, &rec.Secret, &rec.Label, &rec.Confirmed, &rec.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.TOTPRecord{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.TOTPRecord{}, fmt.Errorf("get totp: %w", err)
	}
	return rec, nil
}

func (r *mfaRepo) ConfirmTOTP(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE mfa_totp SET confirmed = TRUE WHERE id = $1`, id)
	return err
}

func (r *mfaRepo) ListTOTP(ctx context.Context, userID string) ([]storage.TOTPRecord, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, secret, label, confirmed, created_at FROM mfa_totp WHERE user_id = $1 AND confirmed = TRUE`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list totp: %w", err)
	}
	defer rows.Close()
	var records []storage.TOTPRecord
	for rows.Next() {
		var rec storage.TOTPRecord
		if err := rows.Scan(&rec.ID, &rec.UserID, &rec.Secret, &rec.Label, &rec.Confirmed, &rec.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

func (r *mfaRepo) CreateWebAuthnCredential(ctx context.Context, c storage.WebAuthnCredential) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO mfa_webauthn (user_id, credential_id, public_key, aaguid, sign_count, name)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		c.UserID, c.CredentialID, c.PublicKey, c.AAGUID, c.SignCount, c.Name)
	return err
}

func (r *mfaRepo) GetWebAuthnCredentials(ctx context.Context, userID string) ([]storage.WebAuthnCredential, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, credential_id, public_key, aaguid, sign_count, name, created_at
		 FROM mfa_webauthn WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("get webauthn credentials: %w", err)
	}
	defer rows.Close()
	var creds []storage.WebAuthnCredential
	for rows.Next() {
		var c storage.WebAuthnCredential
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
			&c.AAGUID, &c.SignCount, &c.Name, &c.CreatedAt); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func (r *mfaRepo) UpdateWebAuthnSignCount(ctx context.Context, credID []byte, signCount uint32) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE mfa_webauthn SET sign_count = $1 WHERE credential_id = $2`,
		signCount, credID)
	return err
}

func (r *mfaRepo) SaveWebAuthnSession(ctx context.Context, userID, data string) (string, error) {
	var id string
	err := r.pool.QueryRow(ctx,
		`INSERT INTO webauthn_sessions (user_id, data) VALUES ($1, $2) RETURNING id`,
		userID, data).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("save webauthn session: %w", err)
	}
	return id, nil
}

func (r *mfaRepo) GetWebAuthnSession(ctx context.Context, sessionID string) (string, error) {
	var data string
	err := r.pool.QueryRow(ctx,
		`SELECT data FROM webauthn_sessions WHERE id = $1 AND expires_at > now()`,
		sessionID).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", storage.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get webauthn session: %w", err)
	}
	return data, nil
}

func (r *mfaRepo) DeleteWebAuthnSession(ctx context.Context, sessionID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM webauthn_sessions WHERE id = $1`, sessionID)
	return err
}
