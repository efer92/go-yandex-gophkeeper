package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type vaultRepo struct{ pool *pgxpool.Pool }

func (r *vaultRepo) Create(ctx context.Context, item storage.VaultItem) (storage.VaultItem, error) {
	const q = `
		INSERT INTO vault_items (user_id, type, payload, metadata)
		VALUES ($1, $2, $3, $4)
		RETURNING id, version, created_at, updated_at`
	err := r.pool.QueryRow(ctx, q, item.UserID, item.Type, item.Payload, item.Metadata).
		Scan(&item.ID, &item.Version, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return storage.VaultItem{}, fmt.Errorf("create vault item: %w", err)
	}
	return item, nil
}

func (r *vaultRepo) Get(ctx context.Context, id, userID string) (storage.VaultItem, error) {
	const q = `
		SELECT id, user_id, type, payload, metadata, version, created_at, updated_at
		FROM vault_items WHERE id = $1 AND user_id = $2`
	return r.scanItem(r.pool.QueryRow(ctx, q, id, userID))
}

func (r *vaultRepo) Update(ctx context.Context, item storage.VaultItem) (storage.VaultItem, error) {
	const q = `
		UPDATE vault_items
		SET payload = $1, metadata = $2, version = version + 1, updated_at = now()
		WHERE id = $3 AND user_id = $4
		RETURNING id, user_id, type, payload, metadata, version, created_at, updated_at`
	return r.scanItem(r.pool.QueryRow(ctx, q, item.Payload, item.Metadata, item.ID, item.UserID))
}

func (r *vaultRepo) Delete(ctx context.Context, id, userID string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM vault_items WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("delete vault item: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (r *vaultRepo) List(ctx context.Context, userID string, f storage.ListFilter) ([]storage.VaultItem, string, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var sb strings.Builder
	args := []any{userID}
	sb.WriteString(`SELECT id, user_id, type, payload, metadata, version, created_at, updated_at
		FROM vault_items WHERE user_id = $1`)

	if f.TypeFilter != "" {
		args = append(args, f.TypeFilter)
		fmt.Fprintf(&sb, " AND type = $%d", len(args))
	}
	if f.Cursor != "" {
		args = append(args, f.Cursor)
		fmt.Fprintf(&sb, " AND id > $%d", len(args))
	}
	args = append(args, limit+1)
	fmt.Fprintf(&sb, " ORDER BY updated_at DESC, id LIMIT $%d", len(args))

	rows, err := r.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, "", fmt.Errorf("list vault items: %w", err)
	}
	defer rows.Close()

	var items []storage.VaultItem
	for rows.Next() {
		item, err := r.scanRow(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, item)
	}

	var nextCursor string
	if len(items) > limit {
		nextCursor = items[limit].ID
		items = items[:limit]
	}
	return items, nextCursor, nil
}

func (r *vaultRepo) scanItem(row pgx.Row) (storage.VaultItem, error) {
	var item storage.VaultItem
	err := row.Scan(&item.ID, &item.UserID, &item.Type, &item.Payload,
		&item.Metadata, &item.Version, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.VaultItem{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.VaultItem{}, fmt.Errorf("scan vault item: %w", err)
	}
	return item, nil
}

func (r *vaultRepo) scanRow(rows pgx.Rows) (storage.VaultItem, error) {
	var item storage.VaultItem
	err := rows.Scan(&item.ID, &item.UserID, &item.Type, &item.Payload,
		&item.Metadata, &item.Version, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}
