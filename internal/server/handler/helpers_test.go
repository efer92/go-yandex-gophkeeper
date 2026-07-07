package handler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
)

func TestUserIDFromCtx_Present(t *testing.T) {
	ctx := middleware.ContextWithUserID(context.Background(), "user-42")
	id, ok := userIDFromCtx(ctx)
	assert.True(t, ok)
	assert.Equal(t, "user-42", id)
}

func TestUserIDFromCtx_Missing(t *testing.T) {
	id, ok := userIDFromCtx(context.Background())
	assert.False(t, ok)
	assert.Empty(t, id)
}
