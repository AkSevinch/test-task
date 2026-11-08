// Command server запускает сервис обмена информацией об угрозах
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"threat-exchange/internal/api"
	"threat-exchange/internal/config"
	"threat-exchange/internal/service"
	"threat-exchange/internal/store"
)

const databaseReadyTimeout = 30 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}

func run(baseLogger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	threatStore, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer threatStore.Close()

	if err := waitForDatabase(ctx, threatStore, logger); err != nil {
		return err
	}
	if err := threatStore.Migrate(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	threatService := service.New(threatStore)
	router, err := api.NewRouter(threatService, threatStore, logger)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           router,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("server listening", "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("server stopped")
	return nil
}

func waitForDatabase(ctx context.Context, threatStore *store.Postgres, logger *slog.Logger) error {
	deadline := time.Now().Add(databaseReadyTimeout)
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := threatStore.Ping(pingCtx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("database is not ready after %s: %w", databaseReadyTimeout, err)
		}
		logger.Warn("database is not ready yet", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
