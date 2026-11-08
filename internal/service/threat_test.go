package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"threat-exchange/internal/domain"
	"threat-exchange/internal/store"
	"threat-exchange/internal/store/memory"
)

var fixedNow = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

func newTestService() (*Service, *memory.Store) {
	threatStore := memory.New()
	svc := New(threatStore)
	svc.now = func() time.Time { return fixedNow }
	return svc, threatStore
}

func TestCreateAppliesDefaults(t *testing.T) {
	svc, memoryStore := newTestService()

	threat, err := svc.Create(context.Background(), CreateInput{
		MD5:  strings.Repeat("A", 32),
		Name: "  Trojan.Win32.Generic  ",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if threat.MD5 != strings.Repeat("a", 32) {
		t.Errorf("MD5 = %q, want lowercase hash", threat.MD5)
	}
	if threat.Name != "Trojan.Win32.Generic" {
		t.Errorf("Name = %q, want trimmed name", threat.Name)
	}
	if threat.ThreatType != domain.DefaultThreatType {
		t.Errorf("ThreatType = %q, want %q", threat.ThreatType, domain.DefaultThreatType)
	}
	if threat.Severity != domain.DefaultSeverity {
		t.Errorf("Severity = %q, want %q", threat.Severity, domain.DefaultSeverity)
	}
	if threat.Status != domain.DefaultStatus {
		t.Errorf("Status = %q, want %q", threat.Status, domain.DefaultStatus)
	}
	if threat.Source != domain.DefaultSource {
		t.Errorf("Source = %q, want %q", threat.Source, domain.DefaultSource)
	}
	if threat.Tags == nil || len(threat.Tags) != 0 {
		t.Errorf("Tags = %#v, want empty slice", threat.Tags)
	}
	if !threat.CreatedAt.Equal(fixedNow) || !threat.UpdatedAt.Equal(fixedNow) {
		t.Errorf("timestamps = %v/%v, want %v", threat.CreatedAt, threat.UpdatedAt, fixedNow)
	}

	stored, err := memoryStore.Get(context.Background(), threat.MD5)
	if err != nil {
		t.Fatalf("stored threat not found: %v", err)
	}
	if stored.Name != threat.Name {
		t.Errorf("stored Name = %q, want %q", stored.Name, threat.Name)
	}
}

func TestCreateAppliesOptionalFields(t *testing.T) {
	svc, _ := newTestService()

	threatType := domain.ThreatTypeRansomware
	severity := domain.SeverityCritical
	status := domain.StatusUnderReview
	description := "  encrypts files  "
	fileType := " PE32 executable "
	fileSize := int64(12345)
	confidence := 87
	tags := []string{" banker ", "windows"}
	source := " feed "
	firstSeen := time.Date(2026, time.January, 1, 10, 0, 0, 0, time.FixedZone("UTC+3", 3*60*60))
	lastSeen := firstSeen.Add(24 * time.Hour)

	threat, err := svc.Create(context.Background(), CreateInput{
		MD5:         strings.Repeat("b", 32),
		Name:        "Ransom",
		ThreatType:  &threatType,
		Severity:    &severity,
		Status:      &status,
		Description: &description,
		FileType:    &fileType,
		FileSize:    &fileSize,
		Confidence:  &confidence,
		Tags:        &tags,
		Source:      &source,
		FirstSeen:   &firstSeen,
		LastSeen:    &lastSeen,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if threat.ThreatType != threatType || threat.Severity != severity || threat.Status != status {
		t.Errorf("enum fields = %q/%q/%q", threat.ThreatType, threat.Severity, threat.Status)
	}
	if threat.Description != "encrypts files" || threat.FileType != "PE32 executable" {
		t.Errorf("description/file_type = %q/%q", threat.Description, threat.FileType)
	}
	if threat.FileSize != fileSize {
		t.Errorf("FileSize = %d, want %d", threat.FileSize, fileSize)
	}
	if threat.Confidence == nil || *threat.Confidence != confidence {
		t.Errorf("Confidence = %v, want %d", threat.Confidence, confidence)
	}
	if got, want := strings.Join(threat.Tags, ","), "banker,windows"; got != want {
		t.Errorf("Tags = %q, want %q", got, want)
	}
	if threat.Source != "feed" {
		t.Errorf("Source = %q, want feed", threat.Source)
	}
	if threat.FirstSeen == nil || threat.FirstSeen.Location() != time.UTC {
		t.Errorf("FirstSeen = %v, want UTC", threat.FirstSeen)
	}
}

func TestCreateValidation(t *testing.T) {
	longName := strings.Repeat("a", 201)
	longDescription := strings.Repeat("a", 4097)
	longTag := strings.Repeat("a", 65)
	tooManyTags := make([]string, 21)
	for i := range tooManyTags {
		tooManyTags[i] = string(rune('a' + i))
	}
	invalidType := domain.ThreatType("malware")
	invalidSeverity := domain.Severity("extreme")
	invalidStatus := domain.Status("done")
	badConfidence := 101
	negativeSize := int64(-1)
	firstSeen := fixedNow
	lastSeen := fixedNow.Add(-time.Hour)

	tagsWithEmpty := []string{"ok", " "}
	tagsWithDuplicate := []string{"dup", " dup "}

	tests := []struct {
		name  string
		input CreateInput
		field string
	}{
		{name: "invalid md5", input: CreateInput{MD5: "xyz", Name: "n"}, field: "md5"},
		{name: "blank name", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "   "}, field: "name"},
		{name: "long name", input: CreateInput{MD5: strings.Repeat("c", 32), Name: longName}, field: "name"},
		{name: "invalid type", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", ThreatType: &invalidType}, field: "threat_type"},
		{name: "invalid severity", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Severity: &invalidSeverity}, field: "severity"},
		{name: "invalid status", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Status: &invalidStatus}, field: "status"},
		{name: "long description", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Description: &longDescription}, field: "description"},
		{name: "negative size", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", FileSize: &negativeSize}, field: "file_size"},
		{name: "confidence too high", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Confidence: &badConfidence}, field: "confidence"},
		{name: "empty tag", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Tags: &tagsWithEmpty}, field: "tags"},
		{name: "duplicate tag", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Tags: &tagsWithDuplicate}, field: "tags"},
		{name: "too many tags", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Tags: &tooManyTags}, field: "tags"},
		{name: "long tag", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", Tags: &[]string{longTag}}, field: "tags"},
		{name: "last seen before first seen", input: CreateInput{MD5: strings.Repeat("c", 32), Name: "n", FirstSeen: &firstSeen, LastSeen: &lastSeen}, field: "last_seen"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService()
			_, err := svc.Create(context.Background(), tc.input)
			var validationErr *domain.ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %v, want *domain.ValidationError", err)
			}
			if validationErr.Field != tc.field {
				t.Errorf("field = %q, want %q", validationErr.Field, tc.field)
			}
		})
	}
}

func TestCreateConflict(t *testing.T) {
	svc, _ := newTestService()
	input := CreateInput{MD5: strings.Repeat("d", 32), Name: "Threat"}

	if _, err := svc.Create(context.Background(), input); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	if _, err := svc.Create(context.Background(), input); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second Create() error = %v, want ErrConflict", err)
	}
}

func TestUpdateReplacesRecordAndPreservesCreatedAt(t *testing.T) {
	svc, _ := newTestService()
	md5 := strings.Repeat("e", 32)
	initialType := domain.ThreatTypeSpyware
	initialSeverity := domain.SeverityHigh
	initialDescription := "initial"
	initialTags := []string{"old"}

	created, err := svc.Create(context.Background(), CreateInput{
		MD5:         md5,
		Name:        "Original",
		ThreatType:  &initialType,
		Severity:    &initialSeverity,
		Description: &initialDescription,
		Tags:        &initialTags,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	later := fixedNow.Add(2 * time.Hour)
	svc.now = func() time.Time { return later }

	updated, err := svc.Update(context.Background(), strings.ToUpper(md5), UpdateInput{
		Name: "Updated",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if updated.MD5 != md5 {
		t.Errorf("MD5 = %q, want %q", updated.MD5, md5)
	}
	if updated.Name != "Updated" {
		t.Errorf("Name = %q, want Updated", updated.Name)
	}
	if updated.ThreatType != domain.DefaultThreatType {
		t.Errorf("ThreatType = %q, want reset default %q", updated.ThreatType, domain.DefaultThreatType)
	}
	if updated.Severity != domain.DefaultSeverity {
		t.Errorf("Severity = %q, want reset default %q", updated.Severity, domain.DefaultSeverity)
	}
	if updated.Description != "" {
		t.Errorf("Description = %q, want empty", updated.Description)
	}
	if len(updated.Tags) != 0 {
		t.Errorf("Tags = %#v, want empty", updated.Tags)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("CreatedAt = %v, want preserved %v", updated.CreatedAt, created.CreatedAt)
	}
	if !updated.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", updated.UpdatedAt, later)
	}
}

func TestUpdateNotFound(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.Update(context.Background(), strings.Repeat("f", 32), UpdateInput{Name: "Updated"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update() error = %v, want ErrNotFound", err)
	}
}

func TestGet(t *testing.T) {
	svc, _ := newTestService()
	md5 := strings.Repeat("1", 32)
	if _, err := svc.Create(context.Background(), CreateInput{MD5: md5, Name: "Threat"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	threat, err := svc.Get(context.Background(), strings.ToUpper(md5))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if threat.MD5 != md5 {
		t.Errorf("MD5 = %q, want %q", threat.MD5, md5)
	}

	if _, err := svc.Get(context.Background(), strings.Repeat("2", 32)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get() error = %v, want ErrNotFound", err)
	}
	if _, err := svc.Get(context.Background(), "not-a-hash"); err == nil {
		t.Error("Get() with invalid md5 returned nil error")
	}
}
