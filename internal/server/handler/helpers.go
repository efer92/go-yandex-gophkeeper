package handler

import (
	"context"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
)

func userIDFromCtx(ctx context.Context) (string, bool) {
	return middleware.UserIDFromContext(ctx)
}
