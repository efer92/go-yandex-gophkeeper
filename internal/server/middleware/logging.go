package middleware

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// LoggingInterceptor logs each unary RPC with method, duration, and status code.
func LoggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		st, _ := status.FromError(err)
		logger.Info("rpc",
			zap.String("method", info.FullMethod),
			zap.String("code", st.Code().String()),
			zap.Duration("duration", time.Since(start)),
		)
		return resp, err
	}
}
