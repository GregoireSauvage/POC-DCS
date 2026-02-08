package http

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func newTestServerWithAuth(t *testing.T) (*Server, *auth.JWTService) {
	t.Helper()
	cfg := &config.Config{
		Env:             "dev",
		Service:         "backend-go-test",
		HTTPAddr:        ":0",
		GRPCAddr:        ":0",
		LogLevel:        slog.LevelError,
		DCSMode:         "on",
		CacheLevel:      1,
		CacheMaxEntries: 100,
		JWTSecret:       "test-secret",
		JWTIssuer:       "test-issuer",
		JWTAudience:     "test-audience",
		JWTTTLMin:       60,
	}
	server := NewServer(cfg, slog.Default(), nil) // nil DB for test
	jwtSvc := auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTLMin)
	return server, jwtSvc
}

func generateToken(t *testing.T, jwtSvc *auth.JWTService, role string) string {
	t.Helper()
	principal := types.Principal{
		UserID:   "test-user-id",
		TenantID: "test-tenant",
		Username: "testuser",
		Role:     role,
	}
	token, err := jwtSvc.GenerateToken(principal, "")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
}

func TestAdminSettings_NoJWT_Returns401(t *testing.T) {
	server, _ := newTestServerWithAuth(t)

	tests := []struct {
		name   string
		method string
		body   interface{}
	}{
		{"GET without JWT", http.MethodGet, nil},
		{"PATCH without JWT", http.MethodPatch, map[string]interface{}{"dcs_mode": "off"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody *bytes.Reader
			if tt.body != nil {
				bodyBytes, _ := json.Marshal(tt.body)
				reqBody = bytes.NewReader(bodyBytes)
			} else {
				reqBody = bytes.NewReader([]byte{})
			}

			req := httptest.NewRequest(tt.method, "/admin/settings", reqBody)
			if tt.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()

			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s /admin/settings without JWT: expected 401, got %d", tt.method, rec.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if _, ok := response["detail"]; !ok {
				t.Error("expected error detail in response")
			}
		})
	}
}

func TestAdminSettings_NonAdminRole_Returns403(t *testing.T) {
	server, jwtSvc := newTestServerWithAuth(t)

	nonAdminRoles := []string{"developer", "agent", "user", "guest"}

	for _, role := range nonAdminRoles {
		t.Run("role="+role, func(t *testing.T) {
			token := generateToken(t, jwtSvc, role)

			// Test GET
			req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("GET /admin/settings with role=%s: expected 403, got %d", role, rec.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if detail, ok := response["detail"].(string); !ok || detail != "admin role required" {
				t.Errorf("expected 'admin role required' error, got: %v", response["detail"])
			}

			// Test PATCH
			payload := map[string]interface{}{"dcs_mode": "off"}
			bodyBytes, _ := json.Marshal(payload)
			req = httptest.NewRequest(http.MethodPatch, "/admin/settings", bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			rec = httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("PATCH /admin/settings with role=%s: expected 403, got %d", role, rec.Code)
			}
		})
	}
}

func TestAdminSettings_AdminRole_Returns200(t *testing.T) {
	server, jwtSvc := newTestServerWithAuth(t)

	adminToken := generateToken(t, jwtSvc, "admin")

	// Test GET
	t.Run("GET as admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()

		server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET /admin/settings with admin role: expected 200, got %d", rec.Code)
		}

		var settings map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &settings); err != nil {
			t.Fatalf("failed to parse settings response: %v", err)
		}

		if _, ok := settings["dcs_mode"]; !ok {
			t.Error("expected dcs_mode in response")
		}
		if _, ok := settings["cache_level"]; !ok {
			t.Error("expected cache_level in response")
		}
	})

	// Test PATCH
	t.Run("PATCH as admin", func(t *testing.T) {
		payload := map[string]interface{}{"dcs_mode": "off", "cache_level": 2}
		bodyBytes, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPatch, "/admin/settings", bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("PATCH /admin/settings with admin role: expected 200, got %d", rec.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if response["dcs_mode"] != "off" {
			t.Errorf("expected dcs_mode=off after patch, got %v", response["dcs_mode"])
		}

		// Verify settings were actually updated
		req = httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec = httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)

		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to parse verification response: %v", err)
		}
		if response["dcs_mode"] != "off" {
			t.Error("settings were not persisted correctly")
		}
	})
}

func TestAdminSettings_InvalidJWT_Returns401(t *testing.T) {
	server, _ := newTestServerWithAuth(t)

	invalidTokens := []struct {
		name  string
		token string
	}{
		{"malformed token", "not-a-jwt-token"},
		{"empty token", ""},
		{"wrong signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalid"},
	}

	for _, tt := range invalidTokens {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := httptest.NewRecorder()

			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("GET /admin/settings with %s: expected 401, got %d", tt.name, rec.Code)
			}
		})
	}
}

func TestAdminSettings_MissingBearerPrefix_Returns401(t *testing.T) {
	server, jwtSvc := newTestServerWithAuth(t)

	adminToken := generateToken(t, jwtSvc, "admin")

	req := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)
	// Set token without "Bearer " prefix
	req.Header.Set("Authorization", adminToken)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /admin/settings without Bearer prefix: expected 401, got %d", rec.Code)
	}
}
