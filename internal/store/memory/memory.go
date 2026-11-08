// Package memory хранит угрозы в памяти для тестов
package memory

import (
	"context"
	"sync"

	"threat-exchange/internal/domain"
	"threat-exchange/internal/store"
)

// Store реализует store.ThreatStore в памяти
type Store struct {
	mu      sync.RWMutex
	threats map[string]domain.Threat
}

func New() *Store {
	return &Store{threats: make(map[string]domain.Threat)}
}

// Create вставляет угрозу, дубль MD5 даёт store.ErrConflict
func (s *Store) Create(_ context.Context, threat *domain.Threat) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.threats[threat.MD5]; exists {
		return store.ErrConflict
	}
	s.threats[threat.MD5] = clone(*threat)
	return nil
}

// Get возвращает копию угрозы
func (s *Store) Get(_ context.Context, md5 string) (*domain.Threat, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	threat, exists := s.threats[md5]
	if !exists {
		return nil, store.ErrNotFound
	}
	result := clone(threat)
	return &result, nil
}

// Update заменяет угрозу и сохраняет created_at
func (s *Store) Update(_ context.Context, threat *domain.Threat) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.threats[threat.MD5]
	if !exists {
		return store.ErrNotFound
	}
	threat.CreatedAt = existing.CreatedAt
	s.threats[threat.MD5] = clone(*threat)
	return nil
}

// Ping всегда успешен
func (s *Store) Ping(context.Context) error {
	return nil
}

func clone(threat domain.Threat) domain.Threat {
	result := threat
	result.Tags = append([]string(nil), threat.Tags...)
	if threat.Confidence != nil {
		confidence := *threat.Confidence
		result.Confidence = &confidence
	}
	if threat.FirstSeen != nil {
		firstSeen := *threat.FirstSeen
		result.FirstSeen = &firstSeen
	}
	if threat.LastSeen != nil {
		lastSeen := *threat.LastSeen
		result.LastSeen = &lastSeen
	}
	return result
}
