// Command server is the GophKeeper server binary.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/efer92/go-yandex-gophkeeper/internal/server/app"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/config"
	"github.com/efer92/go-yandex-gophkeeper/internal/server/storage/postgres"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync() //nolint:errcheck

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("load config", zap.Error(err))
	}

	if err := postgres.Migrate(cfg.DatabaseURL); err != nil {
		logger.Fatal("run migrations", zap.Error(err))
	}
	logger.Info("migrations applied")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	application, err := app.New(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("init app", zap.Error(err))
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		logger.Info("shutting down")
		cancel()
		application.Shutdown()
	}()

	if err := application.Run(); err != nil {
		logger.Error("server stopped", zap.Error(err))
	}
}
