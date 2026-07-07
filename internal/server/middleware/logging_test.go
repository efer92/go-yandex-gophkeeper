package middleware_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
)

func TestLoggingInterceptor_SuccessPath(t *testing.T) {
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.AddCaller()))
	interceptor := middleware.LoggingInterceptor(logger)

	called := false
	_, err := interceptor(context.Background(), "req",
		&grpc.UnaryServerInfo{FullMethod: "/vault.VaultService/ListItems"},
		func(_ context.Context, req any) (any, error) {
			called = true
			return "resp", nil
		})
	require.NoError(t, err)
	assert.True(t, called, "handler must be called")
}

func TestLoggingInterceptor_ErrorPath(t *testing.T) {
	logger := zaptest.NewLogger(t)
	interceptor := middleware.LoggingInterceptor(logger)

	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/auth.AuthService/Login"},
		func(_ context.Context, req any) (any, error) {
			return nil, errors.New("boom")
		})
	assert.Error(t, err, "error from handler must propagate")
}
