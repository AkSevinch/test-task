package store

import (
	"context"
	"errors"

	"threat-exchange/internal/domain"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
)

type ThreatStore interface {
	Create(ctx context.Context, threat *domain.Threat) error
	Get(ctx context.Context, md5 string) (*domain.Threat, error)
	Update(ctx context.Context, threat *domain.Threat) error
	Ping(ctx context.Context) error
}
