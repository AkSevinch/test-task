package service

import (
	"context"
	"time"

	"threat-exchange/internal/domain"
	"threat-exchange/internal/store"
)

type CreateInput struct {
	MD5         string
	Name        string
	ThreatType  *domain.ThreatType
	Severity    *domain.Severity
	Status      *domain.Status
	Description *string
	FileType    *string
	FileSize    *int64
	Confidence  *int
	Tags        *[]string
	Source      *string
	FirstSeen   *time.Time
	LastSeen    *time.Time
}

type UpdateInput struct {
	Name        string
	ThreatType  *domain.ThreatType
	Severity    *domain.Severity
	Status      *domain.Status
	Description *string
	FileType    *string
	FileSize    *int64
	Confidence  *int
	Tags        *[]string
	Source      *string
	FirstSeen   *time.Time
	LastSeen    *time.Time
}

type Service struct {
	store store.ThreatStore
	now   func() time.Time
}

func New(threatStore store.ThreatStore) *Service {
	return &Service{store: threatStore, now: time.Now}
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*domain.Threat, error) {
	md5, err := domain.NormalizeMD5(in.MD5)
	if err != nil {
		return nil, err
	}

	threat := &domain.Threat{
		MD5:  md5,
		Name: in.Name,
		Tags: []string{},
	}
	applyOptional(threat, optionalFields{
		threatType:  in.ThreatType,
		severity:    in.Severity,
		status:      in.Status,
		description: in.Description,
		fileType:    in.FileType,
		fileSize:    in.FileSize,
		confidence:  in.Confidence,
		tags:        in.Tags,
		source:      in.Source,
		firstSeen:   in.FirstSeen,
		lastSeen:    in.LastSeen,
	})

	threat.Normalize()
	if err := threat.Validate(); err != nil {
		return nil, err
	}

	now := s.now().UTC()
	threat.CreatedAt = now
	threat.UpdatedAt = now

	if err := s.store.Create(ctx, threat); err != nil {
		return nil, err
	}
	return threat, nil
}

func (s *Service) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	normalized, err := domain.NormalizeMD5(md5)
	if err != nil {
		return nil, err
	}
	return s.store.Get(ctx, normalized)
}

func (s *Service) Update(ctx context.Context, md5 string, in UpdateInput) (*domain.Threat, error) {
	normalized, err := domain.NormalizeMD5(md5)
	if err != nil {
		return nil, err
	}

	threat := &domain.Threat{
		MD5:  normalized,
		Name: in.Name,
		Tags: []string{},
	}
	applyOptional(threat, optionalFields{
		threatType:  in.ThreatType,
		severity:    in.Severity,
		status:      in.Status,
		description: in.Description,
		fileType:    in.FileType,
		fileSize:    in.FileSize,
		confidence:  in.Confidence,
		tags:        in.Tags,
		source:      in.Source,
		firstSeen:   in.FirstSeen,
		lastSeen:    in.LastSeen,
	})

	threat.Normalize()
	if err := threat.Validate(); err != nil {
		return nil, err
	}

	threat.UpdatedAt = s.now().UTC()

	if err := s.store.Update(ctx, threat); err != nil {
		return nil, err
	}
	return threat, nil
}

type optionalFields struct {
	threatType  *domain.ThreatType
	severity    *domain.Severity
	status      *domain.Status
	description *string
	fileType    *string
	fileSize    *int64
	confidence  *int
	tags        *[]string
	source      *string
	firstSeen   *time.Time
	lastSeen    *time.Time
}

func applyOptional(threat *domain.Threat, in optionalFields) {
	if in.threatType != nil {
		threat.ThreatType = *in.threatType
	}
	if in.severity != nil {
		threat.Severity = *in.severity
	}
	if in.status != nil {
		threat.Status = *in.status
	}
	if in.description != nil {
		threat.Description = *in.description
	}
	if in.fileType != nil {
		threat.FileType = *in.fileType
	}
	if in.fileSize != nil {
		threat.FileSize = *in.fileSize
	}
	if in.confidence != nil {
		confidence := *in.confidence
		threat.Confidence = &confidence
	}
	if in.tags != nil {
		threat.Tags = append([]string(nil), (*in.tags)...)
	}
	if in.source != nil {
		threat.Source = *in.source
	}
	if in.firstSeen != nil {
		firstSeen := *in.firstSeen
		threat.FirstSeen = &firstSeen
	}
	if in.lastSeen != nil {
		lastSeen := *in.lastSeen
		threat.LastSeen = &lastSeen
	}
}
