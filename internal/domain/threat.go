// Package domain содержит модель угрозы и правила валидации
package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type ThreatType string

// Известные типы угроз
const (
	ThreatTypeTrojan     ThreatType = "trojan"
	ThreatTypeVirus      ThreatType = "virus"
	ThreatTypeWorm       ThreatType = "worm"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeSpyware    ThreatType = "spyware"
	ThreatTypeAdware     ThreatType = "adware"
	ThreatTypeRootkit    ThreatType = "rootkit"
	ThreatTypeBackdoor   ThreatType = "backdoor"
	ThreatTypeMiner      ThreatType = "miner"
	ThreatTypePUA        ThreatType = "pua"
	ThreatTypeOther      ThreatType = "other"
)

func (t ThreatType) Valid() bool {
	switch t {
	case ThreatTypeTrojan, ThreatTypeVirus, ThreatTypeWorm, ThreatTypeRansomware,
		ThreatTypeSpyware, ThreatTypeAdware, ThreatTypeRootkit, ThreatTypeBackdoor,
		ThreatTypeMiner, ThreatTypePUA, ThreatTypeOther:
		return true
	default:
		return false
	}
}

type Severity string

// Известные уровни критичности
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

type Status string

// Известные статусы
const (
	StatusActive        Status = "active"
	StatusInactive      Status = "inactive"
	StatusFalsePositive Status = "false_positive"
	StatusUnderReview   Status = "under_review"
)

func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusInactive, StatusFalsePositive, StatusUnderReview:
		return true
	default:
		return false
	}
}

// Значения по умолчанию для необязательных полей
const (
	DefaultThreatType = ThreatTypeOther
	DefaultSeverity   = SeverityMedium
	DefaultStatus     = StatusActive
	DefaultSource     = "manual"

	maxNameLen        = 200
	maxDescriptionLen = 4096
	maxFileTypeLen    = 255
	maxSourceLen      = 64
	maxTags           = 20
	maxTagLen         = 64
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

type Threat struct {
	MD5         string
	Name        string
	ThreatType  ThreatType
	Severity    Severity
	Status      Status
	Description string
	FileType    string
	FileSize    int64
	Confidence  *int
	Tags        []string
	Source      string
	FirstSeen   *time.Time
	LastSeen    *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ValidationError описывает невалидное поле
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// NormalizeMD5 обрезает, приводит к нижнему регистру и проверяет MD5
func NormalizeMD5(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !md5Pattern.MatchString(value) {
		return "", &ValidationError{Field: "md5", Message: "must be a 32-character hexadecimal string"}
	}
	return value, nil
}

// Normalize приводит угрозу к каноническому виду и ставит дефолты
// Результат нужно отдельно проверить через Validate
func (t *Threat) Normalize() {
	t.MD5 = strings.ToLower(strings.TrimSpace(t.MD5))
	t.Name = strings.TrimSpace(t.Name)
	t.Description = strings.TrimSpace(t.Description)
	t.FileType = strings.TrimSpace(t.FileType)
	t.Source = strings.TrimSpace(t.Source)

	if t.ThreatType == "" {
		t.ThreatType = DefaultThreatType
	}
	if t.Severity == "" {
		t.Severity = DefaultSeverity
	}
	if t.Status == "" {
		t.Status = DefaultStatus
	}
	if t.Source == "" {
		t.Source = DefaultSource
	}

	if t.Tags == nil {
		t.Tags = []string{}
	}
	tags := make([]string, 0, len(t.Tags))
	for _, tag := range t.Tags {
		tags = append(tags, strings.TrimSpace(tag))
	}
	t.Tags = tags

	if t.FirstSeen != nil {
		utc := t.FirstSeen.UTC()
		t.FirstSeen = &utc
	}
	if t.LastSeen != nil {
		utc := t.LastSeen.UTC()
		t.LastSeen = &utc
	}
}

// Validate проверяет бизнес-правила нормализованной угрозы
func (t *Threat) Validate() error {
	if _, err := NormalizeMD5(t.MD5); err != nil {
		return err
	}
	if err := validateName(t.Name); err != nil {
		return err
	}
	if !t.ThreatType.Valid() {
		return &ValidationError{Field: "threat_type", Message: "unknown threat type"}
	}
	if !t.Severity.Valid() {
		return &ValidationError{Field: "severity", Message: "must be one of low, medium, high, critical"}
	}
	if !t.Status.Valid() {
		return &ValidationError{Field: "status", Message: "must be one of active, inactive, false_positive, under_review"}
	}
	if utf8.RuneCountInString(t.Description) > maxDescriptionLen {
		return &ValidationError{Field: "description", Message: fmt.Sprintf("must be at most %d characters", maxDescriptionLen)}
	}
	if utf8.RuneCountInString(t.FileType) > maxFileTypeLen {
		return &ValidationError{Field: "file_type", Message: fmt.Sprintf("must be at most %d characters", maxFileTypeLen)}
	}
	if t.FileSize < 0 {
		return &ValidationError{Field: "file_size", Message: "must be greater than or equal to 0"}
	}
	if t.Confidence != nil && (*t.Confidence < 0 || *t.Confidence > 100) {
		return &ValidationError{Field: "confidence", Message: "must be between 0 and 100"}
	}
	if err := validateTags(t.Tags); err != nil {
		return err
	}
	if utf8.RuneCountInString(t.Source) > maxSourceLen {
		return &ValidationError{Field: "source", Message: fmt.Sprintf("must be at most %d characters", maxSourceLen)}
	}
	if t.FirstSeen != nil && t.LastSeen != nil && t.LastSeen.Before(*t.FirstSeen) {
		return &ValidationError{Field: "last_seen", Message: "must not be before first_seen"}
	}
	return nil
}

func validateName(name string) error {
	if name == "" {
		return &ValidationError{Field: "name", Message: "must not be empty"}
	}
	if utf8.RuneCountInString(name) > maxNameLen {
		return &ValidationError{Field: "name", Message: fmt.Sprintf("must be at most %d characters", maxNameLen)}
	}
	return nil
}

func validateTags(tags []string) error {
	if len(tags) > maxTags {
		return &ValidationError{Field: "tags", Message: fmt.Sprintf("must contain at most %d items", maxTags)}
	}
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if tag == "" {
			return &ValidationError{Field: "tags", Message: "must not contain empty values"}
		}
		if utf8.RuneCountInString(tag) > maxTagLen {
			return &ValidationError{Field: "tags", Message: fmt.Sprintf("each tag must be at most %d characters", maxTagLen)}
		}
		if _, ok := seen[tag]; ok {
			return &ValidationError{Field: "tags", Message: fmt.Sprintf("duplicate tag %q", tag)}
		}
		seen[tag] = struct{}{}
	}
	return nil
}
