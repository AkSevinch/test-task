package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"threat-exchange/internal/domain"
)

const threatColumns = `md5, name, threat_type, severity, status, description,
	file_type, file_size, confidence, tags, source, first_seen, last_seen,
	created_at, updated_at`

// Postgres реализует ThreatStore на PostgreSQL
type Postgres struct {
	pool *pgxpool.Pool
}

// Open создаёт пул соединений, подключение ленивое, проверяйте через Ping
func Open(ctx context.Context, databaseURL string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() {
	p.pool.Close()
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// Create вставляет угрозу, нарушение уникальности даёт ErrConflict
func (p *Postgres) Create(ctx context.Context, threat *domain.Threat) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO threats (
			md5, name, threat_type, severity, status, description, file_type,
			file_size, confidence, tags, source, first_seen, last_seen,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
		)`,
		threat.MD5, threat.Name, string(threat.ThreatType), string(threat.Severity),
		string(threat.Status), threat.Description, threat.FileType, threat.FileSize,
		threat.Confidence, threat.Tags, threat.Source, threat.FirstSeen,
		threat.LastSeen, threat.CreatedAt, threat.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmt.Errorf("insert threat: %w", err)
	}
	return nil
}

func (p *Postgres) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	row := p.pool.QueryRow(ctx,
		`SELECT `+threatColumns+` FROM threats WHERE md5 = $1`, md5,
	)
	threat, err := scanThreat(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("select threat: %w", err)
	}
	return threat, nil
}

// Update заменяет угрозу, отсутствие даёт ErrNotFound
func (p *Postgres) Update(ctx context.Context, threat *domain.Threat) error {
	row := p.pool.QueryRow(ctx, `
		UPDATE threats SET
			name = $2,
			threat_type = $3,
			severity = $4,
			status = $5,
			description = $6,
			file_type = $7,
			file_size = $8,
			confidence = $9,
			tags = $10,
			source = $11,
			first_seen = $12,
			last_seen = $13,
			updated_at = $14
		WHERE md5 = $1
		RETURNING created_at`,
		threat.MD5, threat.Name, string(threat.ThreatType), string(threat.Severity),
		string(threat.Status), threat.Description, threat.FileType, threat.FileSize,
		threat.Confidence, threat.Tags, threat.Source, threat.FirstSeen,
		threat.LastSeen, threat.UpdatedAt,
	)
	if err := row.Scan(&threat.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("update threat: %w", err)
	}
	return nil
}

// rowScanner реализует pgx.Row
type rowScanner interface {
	Scan(dest ...any) error
}

func scanThreat(row rowScanner) (*domain.Threat, error) {
	var (
		threat                       domain.Threat
		threatType, severity, status string
	)
	err := row.Scan(
		&threat.MD5,
		&threat.Name,
		&threatType,
		&severity,
		&status,
		&threat.Description,
		&threat.FileType,
		&threat.FileSize,
		&threat.Confidence,
		&threat.Tags,
		&threat.Source,
		&threat.FirstSeen,
		&threat.LastSeen,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if threat.Tags == nil {
		threat.Tags = []string{}
	}
	threat.ThreatType = domain.ThreatType(threatType)
	threat.Severity = domain.Severity(severity)
	threat.Status = domain.Status(status)
	return &threat, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
