// Package postgres provides the PostgreSQL implementation of storage.Store.
package postgres

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	_ "github.com/jackc/pgx/v5/stdlib" // goose uses database/sql

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB wraps a pgxpool and implements storage.Store.
type DB struct {
	pool     *pgxpool.Pool
	users    *userRepo
	sessions *sessionRepo
	vault    *vaultRepo
	mfa      *mfaRepo
	audit    *auditRepo
}

// New creates a pgxpool connection and runs embedded migrations.
func New(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool new: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	db := &DB{
		pool: pool,
	}
	db.users = &userRepo{pool}
	db.sessions = &sessionRepo{pool}
	db.vault = &vaultRepo{pool}
	db.mfa = &mfaRepo{pool}
	db.audit = &auditRepo{pool}
	return db, nil
}

// Migrate runs all pending SQL migrations using goose.
func Migrate(dsn string) error {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		return fmt.Errorf("goose open: %w", err)
	}
	defer func() { _ = db.Close() }()
	return goose.Up(db, "migrations")
}

// Users returns the users sub-store.
func (d *DB) Users() storage.Users { return d.users }

// Sessions returns the sessions sub-store.
func (d *DB) Sessions() storage.Sessions { return d.sessions }

// Vault returns the vault sub-store.
func (d *DB) Vault() storage.Vault { return d.vault }

// MFA returns the MFA sub-store.
func (d *DB) MFA() storage.MFA { return d.mfa }

// Audit returns the audit sub-store.
func (d *DB) Audit() storage.Audit { return d.audit }

// Close releases the database connection pool.
func (d *DB) Close() { d.pool.Close() }

// Ensure DB implements storage.Store at compile time.
var _ storage.Store = (*DB)(nil)
