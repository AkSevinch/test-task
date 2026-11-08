package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"threat-exchange/internal/service"
	"threat-exchange/internal/store/memory"
)

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	threatStore := memory.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router, err := NewRouter(service.New(threatStore), threatStore, logger)
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	return router
}

func perform(t *testing.T, router http.Handler, method, path, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	return payload
}

func TestCreateGetUpdateLifecycle(t *testing.T) {
	router := newTestRouter(t)
	md5 := strings.Repeat("A", 32)

	create := perform(t, router, http.MethodPost, "/info", "application/json", `{
		"md5": "`+md5+`",
		"name": "Ransomware.Sample",
		"threat_type": "ransomware",
		"severity": "critical",
		"status": "active",
		"file_type": "PE32 executable",
		"file_size": 2048,
		"confidence": 95,
		"tags": ["ransom", "windows"],
		"source": "feed",
		"first_seen": "2026-01-01T10:00:00Z",
		"last_seen": "2026-01-02T10:00:00Z"
	}`)
	if create.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", create.Code, create.Body.String())
	}
	created := decodeJSON(t, create)
	if got := created["md5"]; got != strings.Repeat("a", 32) {
		t.Errorf("md5 = %v, want lowercase", got)
	}
	if created["threat_type"] != "ransomware" || created["severity"] != "critical" {
		t.Errorf("enum fields = %v/%v", created["threat_type"], created["severity"])
	}
	if created["created_at"] == "" || created["updated_at"] == "" {
		t.Error("timestamps are missing")
	}
	createdAt := created["created_at"]

	get := perform(t, router, http.MethodGet, "/info/"+strings.ToUpper(md5), "", "")
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", get.Code, get.Body.String())
	}
	if got := decodeJSON(t, get)["name"]; got != "Ransomware.Sample" {
		t.Errorf("GET name = %v", got)
	}

	update := perform(t, router, http.MethodPut, "/info/"+strings.ToUpper(md5), "application/json",
		`{"name": "Updated.Name", "severity": "low"}`)
	if update.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", update.Code, update.Body.String())
	}
	updated := decodeJSON(t, update)
	if updated["name"] != "Updated.Name" || updated["severity"] != "low" {
		t.Errorf("updated fields = %v/%v", updated["name"], updated["severity"])
	}
	if updated["threat_type"] != "other" {
		t.Errorf("threat_type = %v, want reset to default 'other'", updated["threat_type"])
	}
	if tags, ok := updated["tags"].([]any); !ok || len(tags) != 0 {
		t.Errorf("tags = %v, want empty array", updated["tags"])
	}
	if updated["created_at"] != createdAt {
		t.Errorf("created_at changed: %v -> %v", createdAt, updated["created_at"])
	}

	missing := perform(t, router, http.MethodGet, "/info/"+strings.Repeat("b", 32), "", "")
	if missing.Code != http.StatusNotFound {
		t.Errorf("GET missing status = %d, body = %s", missing.Code, missing.Body.String())
	}
	if decodeJSON(t, missing)["message"] != "Threat not found" {
		t.Errorf("unexpected missing response: %s", missing.Body.String())
	}
}

func TestCreateConflict(t *testing.T) {
	router := newTestRouter(t)
	body := `{"md5": "` + strings.Repeat("c", 32) + `", "name": "Threat"}`

	if got := perform(t, router, http.MethodPost, "/info", "application/json", body); got.Code != http.StatusCreated {
		t.Fatalf("first POST status = %d, body = %s", got.Code, got.Body.String())
	}
	conflict := perform(t, router, http.MethodPost, "/info", "application/json", body)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("second POST status = %d, body = %s", conflict.Code, conflict.Body.String())
	}
	if decodeJSON(t, conflict)["message"] != "Threat already exists" {
		t.Errorf("unexpected conflict response: %s", conflict.Body.String())
	}
}

func TestRequestValidation(t *testing.T) {
	router := newTestRouter(t)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{
			name:   "invalid md5 in body",
			method: http.MethodPost,
			path:   "/info",
			body:   `{"md5": "not-a-hash", "name": "Threat"}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "missing required name",
			method: http.MethodPost,
			path:   "/info",
			body:   `{"md5": "` + strings.Repeat("d", 32) + `"}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "unknown field",
			method: http.MethodPost,
			path:   "/info",
			body:   `{"md5": "` + strings.Repeat("d", 32) + `", "name": "Threat", "unexpected": true}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "unknown enum value",
			method: http.MethodPost,
			path:   "/info",
			body:   `{"md5": "` + strings.Repeat("d", 32) + `", "name": "Threat", "severity": "extreme"}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "invalid md5 in path",
			method: http.MethodGet,
			path:   "/info/xyz",
			status: http.StatusBadRequest,
		},
		{
			name:   "md5 in update body is forbidden",
			method: http.MethodPut,
			path:   "/info/" + strings.Repeat("d", 32),
			body:   `{"md5": "` + strings.Repeat("d", 32) + `", "name": "Threat"}`,
			status: http.StatusBadRequest,
		},
		{
			name:   "update missing threat",
			method: http.MethodPut,
			path:   "/info/" + strings.Repeat("e", 32),
			body:   `{"name": "Threat"}`,
			status: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := perform(t, router, tc.method, tc.path, "application/json", tc.body)
			if recorder.Code != tc.status {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, tc.status, recorder.Body.String())
			}
			payload := decodeJSON(t, recorder)
			if payload["message"] == "" {
				t.Errorf("missing error message in %s", recorder.Body.String())
			}
		})
	}
}

func TestRequestBodyLimit(t *testing.T) {
	router := newTestRouter(t)
	request := httptest.NewRequest(http.MethodPost, "/info", bytes.NewReader(make([]byte, maxBodyBytes+1)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestHealthEndpoints(t *testing.T) {
	router := newTestRouter(t)

	for _, path := range []string{"/livez", "/readyz"} {
		recorder := perform(t, router, http.MethodGet, path, "", "")
		if recorder.Code != http.StatusOK {
			t.Errorf("%s status = %d, body = %s", path, recorder.Code, recorder.Body.String())
		}
		if got := decodeJSON(t, recorder)["status"]; got != "ok" {
			t.Errorf("%s status field = %v", path, got)
		}
	}
}

func TestValidationErrorDetailsAreConcise(t *testing.T) {
	router := newTestRouter(t)

	unknownField := perform(t, router, http.MethodPost, "/info", "application/json",
		`{"md5": "`+strings.Repeat("d", 32)+`", "name": "Threat", "unexpected": true}`)
	details, _ := decodeJSON(t, unknownField)["details"].(string)
	if details == "" || !strings.Contains(details, "unexpected") {
		t.Errorf("details = %q, want mention of the offending field", details)
	}
	if strings.Contains(details, "Schema:") || strings.Contains(details, "\n") {
		t.Errorf("details are not concise: %q", details)
	}

	invalidPath := perform(t, router, http.MethodGet, "/info/not-a-hash", "", "")
	details, _ = decodeJSON(t, invalidPath)["details"].(string)
	if !strings.Contains(details, `parameter "md5"`) {
		t.Errorf("details = %q, want a parameter error", details)
	}
}
