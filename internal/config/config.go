// Package config читает настройки сервиса из переменных окружения
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr              string
	DatabaseURL       string
	LogLevel          slog.Level
	ShutdownTimeout   time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ReadHeaderTimeout time.Duration
}

// Load читает окружение и подставляет значения по умолчанию
func Load() (Config, error) {
	port := envOrDefault("PORT", "8080")
	if _, err := strconv.Atoi(port); err != nil {
		return Config{}, fmt.Errorf("invalid PORT %q: %w", port, err)
	}

	level := slog.LevelInfo
	if raw := os.Getenv("LOG_LEVEL"); raw != "" {
		if err := level.UnmarshalText([]byte(strings.ToUpper(raw))); err != nil {
			return Config{}, fmt.Errorf("invalid LOG_LEVEL %q: %w", raw, err)
		}
	}

	databaseURL := envOrDefault(
		"DATABASE_URL",
		"postgres://threat:threat@localhost:5433/threats?sslmode=disable",
	)

	return Config{
		Addr:              ":" + port,
		DatabaseURL:       databaseURL,
		LogLevel:          level,
		ShutdownTimeout:   15 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
