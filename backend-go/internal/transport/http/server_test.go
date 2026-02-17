package http

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres"
)

func testConfig() *config.Config {
	return &config.Config{
		Env:             "dev",
		Service:         "backend-go-test",
		HTTPAddr:        ":0",
		GRPCAddr:        ":0",
		LogLevel:        slog.LevelError,
		DCSMode:         "on",
		CacheLevel:      1,
		CacheMaxEntries: 100,
		PerfSource:      "go",
		JWTSecret:       "test-secret",
		JWTIssuer:       "test-issuer",
		JWTAudience:     "test-audience",
		JWTTTLMin:       60,
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(testConfig(), slog.Default(), nil) // nil DB for test
}

func adminAuthHeader(t *testing.T, s *Server) string {
	t.Helper()
	token, err := s.jwtService.GenerateToken(
		types.Principal{
			UserID:   "admin-id",
			TenantID: "t1",
			Username: "admin",
			Role:     "admin",
		})
	if err != nil {
		t.Fatalf("failed to generate admin token: %v", err)
	}
	return "Bearer " + token
}

func TestServer_AdminSettingsRoundTrip(t *testing.T) {
	s := newTestServer(t)
	authHeader := adminAuthHeader(t, s)

	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET settings, got %d", rec.Code)
	}

	payload := map[string]interface{}{"dcs_mode": "off", "cache_level": 3}
	raw, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPatch, "/admin/settings", bytes.NewReader(raw))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on PATCH settings, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET settings after patch, got %d", rec.Code)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &settings); err != nil {
		t.Fatalf("invalid settings response: %v", err)
	}
	if settings["dcs_mode"] != "off" {
		t.Fatalf("expected dcs_mode off, got %v", settings["dcs_mode"])
	}
}

func TestServer_DcsToggleAffectsFilmRead(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("X-Role", "developer")
	req.Header.Set("X-Tenant-ID", "t1")
	req.Header.Set("X-User-ID", "u1")
	req.Header.Set("X-Username", "dev")

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for films, got %d", rec.Code)
	}
	if rec.Header().Get("x-perf-total-ms") == "" {
		t.Fatalf("expected telemetry header x-perf-total-ms")
	}
	var films []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &films); err != nil {
		t.Fatalf("invalid films response: %v", err)
	}
	if len(films) == 0 {
		t.Fatalf("expected seeded films")
	}
	if films[0]["time_elapsed"] != "1***" {
		t.Fatalf("expected masked time_elapsed with dcs on, got %v", films[0]["time_elapsed"])
	}

	raw, _ := json.Marshal(map[string]interface{}{"dcs_mode": "off"})
	req = httptest.NewRequest(http.MethodPatch, "/admin/settings", bytes.NewReader(raw))
	req.Header.Set("Authorization", adminAuthHeader(t, s))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when disabling dcs, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("X-Role", "developer")
	req.Header.Set("X-Tenant-ID", "t1")
	req.Header.Set("X-User-ID", "u1")
	req.Header.Set("X-Username", "dev")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for films with dcs off, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &films); err != nil {
		t.Fatalf("invalid films response with dcs off: %v", err)
	}
	if len(films) == 0 {
		t.Fatalf("expected seeded films with dcs off")
	}
	if films[0]["time_elapsed"] == "1***" {
		t.Fatalf("expected non-masked value when dcs is off")
	}
}

func TestServer_PerfServiceNilWhenNoDB(t *testing.T) {
	s := newTestServer(t)
	if s.perfService != nil {
		t.Fatalf("expected perfService nil when no DB")
	}
}

func TestServer_PerfServiceWiredWhenDBProvided(t *testing.T) {
	db := &postgres.Pool{}
	s := NewServer(testConfig(), slog.Default(), db)
	if s.perfService == nil {
		t.Fatalf("expected perfService wired when DB provided")
	}
}
