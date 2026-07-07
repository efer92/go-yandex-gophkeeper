// Package app wires all server components together.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	authpb "github.com/efer92/go-yandex-gophkeeper/gen/auth"
	syncpb "github.com/efer92/go-yandex-gophkeeper/gen/sync"
	vaultpb "github.com/efer92/go-yandex-gophkeeper/gen/vault"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/handler"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/middleware"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/service"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage/postgres"
	jwtpkg "github.com/efer92/go-yandex-gophkeeper/internal/shared/jwt"
)

// App holds all server resources.
type App struct {
	grpcServer *grpc.Server
	db         *postgres.DB
	logger     *zap.Logger
	cfg        *config.Config
}

// New builds and configures the application.
func New(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*App, error) {
	db, err := postgres.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	jwtCfg := jwtpkg.DefaultConfig(cfg.JWTSecret)
	jwtCfg.AccessTokenTTL = cfg.AccessTokenTTL
	jwtCfg.RefreshTokenTTL = cfg.RefreshTokenTTL
	jwtMgr := jwtpkg.NewManager(jwtCfg)

	syncSvc := service.NewSyncService()
	authSvc := service.NewAuthService(db, jwtMgr)
	vaultSvc := service.NewVaultService(db, syncSvc)
	mfaSvc := service.NewMFAService(db, jwtMgr, "GophKeeper")

	authH := handler.NewAuthHandler(authSvc, mfaSvc)
	vaultH := handler.NewVaultHandler(vaultSvc)
	syncH := handler.NewSyncHandler(syncSvc, vaultSvc)

	var serverOpts []grpc.ServerOption
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls: %w", err)
	}
	serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})))

	rateLimiter := middleware.NewRateLimiter(5, 10) // 5 req/s, burst 10, per IP

	serverOpts = append(serverOpts,
		grpc.ChainUnaryInterceptor(
			rateLimiter.UnaryInterceptor(),
			middleware.LoggingInterceptor(logger),
			middleware.AuthInterceptor(jwtMgr),
		),
		grpc.ChainStreamInterceptor(
			middleware.AuthStreamInterceptor(jwtMgr),
		),
	)

	grpcServer := grpc.NewServer(serverOpts...)
	authpb.RegisterAuthServiceServer(grpcServer, authH)
	vaultpb.RegisterVaultServiceServer(grpcServer, vaultH)
	syncpb.RegisterSyncServiceServer(grpcServer, syncH)
	reflection.Register(grpcServer)

	return &App{
		grpcServer: grpcServer,
		db:         db,
		logger:     logger,
		cfg:        cfg,
	}, nil
}

// Run starts the gRPC server (blocking).
func (a *App) Run() error {
	lis, err := net.Listen("tcp", a.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", a.cfg.ServerAddr, err)
	}
	a.logger.Info("gRPC server starting", zap.String("addr", a.cfg.ServerAddr))
	return a.grpcServer.Serve(lis)
}

// GracefulStop gracefully stops the gRPC server, causing Run to return.
func (a *App) GracefulStop() {
	a.grpcServer.GracefulStop()
}

// Close releases application resources (database connection pool, etc.).
func (a *App) Close() {
	a.db.Close()
}

// Shutdown gracefully stops the gRPC server and closes the database connection pool.
func (a *App) Shutdown() {
	a.GracefulStop()
	a.Close()
}
