package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"threat-exchange/internal/domain"
)

func TestIntegrationPostgresStore(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL не задан, интеграционный тест пропущен")
	}

	ctx := context.Background()
	pg, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer pg.Close()

	if err := pg.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := pg.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
	if _, err := pg.pool.Exec(ctx, `TRUNCATE TABLE threats`); err != nil {
		t.Fatalf("truncate threats: %v", err)
	}

	createdAt := time.Date(2026, time.November, 8, 12, 0, 0, 123456000, time.UTC)
	firstSeen := time.Date(2026, time.January, 1, 10, 0, 0, 0, time.UTC)
	lastSeen := firstSeen.Add(48 * time.Hour)
	confidence := 95

	threat := &domain.Threat{
		MD5:         strings.Repeat("a", 32),
		Name:        "Ransomware.Sample",
		ThreatType:  domain.ThreatTypeRansomware,
		Severity:    domain.SeverityCritical,
		Status:      domain.StatusUnderReview,
		Description: "encrypts files",
		FileType:    "PE32 executable",
		FileSize:    2048,
		Confidence:  &confidence,
		Tags:        []string{"ransom", "windows"},
		Source:      "feed",
		FirstSeen:   &firstSeen,
		LastSeen:    &lastSeen,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
	}

	if err := pg.Create(ctx, threat); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := pg.Create(ctx, threat); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate Create() error = %v, want ErrConflict", err)
	}

	stored, err := pg.Get(ctx, threat.MD5)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if stored.Name != threat.Name || stored.ThreatType != threat.ThreatType ||
		stored.Severity != threat.Severity || stored.Status != threat.Status {
		t.Errorf("stored fields = %#v", stored)
	}
	if stored.Description != threat.Description || stored.FileType != threat.FileType ||
		stored.FileSize != threat.FileSize || stored.Source != threat.Source {
		t.Errorf("stored file metadata = %#v", stored)
	}
	if stored.Confidence == nil || *stored.Confidence != confidence {
		t.Errorf("Confidence = %v, want %d", stored.Confidence, confidence)
	}
	if got, want := strings.Join(stored.Tags, ","), "ransom,windows"; got != want {
		t.Errorf("Tags = %q, want %q", got, want)
	}
	if stored.FirstSeen == nil || !stored.FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen = %v, want %v", stored.FirstSeen, firstSeen)
	}
	if !stored.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt = %v, want %v", stored.CreatedAt, createdAt)
	}

	updatedAt := createdAt.Add(time.Hour)
	threat.Name = "Updated.Name"
	threat.Severity = domain.SeverityLow
	threat.Tags = []string{}
	threat.Confidence = nil
	threat.FirstSeen = nil
	threat.LastSeen = nil
	threat.UpdatedAt = updatedAt

	if err := pg.Update(ctx, threat); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if !threat.CreatedAt.Equal(createdAt) {
		t.Errorf("Update() CreatedAt = %v, want preserved %v", threat.CreatedAt, createdAt)
	}

	stored, err = pg.Get(ctx, threat.MD5)
	if err != nil {
		t.Fatalf("Get() after update error = %v", err)
	}
	if stored.Name != "Updated.Name" || stored.Severity != domain.SeverityLow {
		t.Errorf("updated fields = %q/%q", stored.Name, stored.Severity)
	}
	if stored.Confidence != nil || stored.FirstSeen != nil || stored.LastSeen != nil {
		t.Errorf("nullable fields were not cleared: %#v", stored)
	}
	if len(stored.Tags) != 0 {
		t.Errorf("Tags = %#v, want empty", stored.Tags)
	}
	if !stored.UpdatedAt.Equal(updatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", stored.UpdatedAt, updatedAt)
	}

	minimal := &domain.Threat{
		MD5:        strings.Repeat("b", 32),
		Name:       "Minimal",
		ThreatType: domain.ThreatTypeOther,
		Severity:   domain.SeverityMedium,
		Status:     domain.StatusActive,
		Tags:       []string{},
		Source:     "manual",
		CreatedAt:  createdAt,
		UpdatedAt:  createdAt,
	}
	if err := pg.Create(ctx, minimal); err != nil {
		t.Fatalf("Create() minimal error = %v", err)
	}
	storedMinimal, err := pg.Get(ctx, minimal.MD5)
	if err != nil {
		t.Fatalf("Get() minimal error = %v", err)
	}
	if storedMinimal.Confidence != nil || storedMinimal.FirstSeen != nil || storedMinimal.LastSeen != nil {
		t.Errorf("minimal nullable fields = %#v", storedMinimal)
	}

	missing := strings.Repeat("f", 32)
	if _, err := pg.Get(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get() missing error = %v, want ErrNotFound", err)
	}
	if err := pg.Update(ctx, &domain.Threat{MD5: missing, Name: "Missing"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update() missing error = %v, want ErrNotFound", err)
	}
}
