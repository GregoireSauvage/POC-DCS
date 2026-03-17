package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
)

func TestBuildAccessContext_UsesJWTClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/films", nil)
	req = req.WithContext(context.WithValue(req.Context(), jwtClaimsKey, &auth.JWTClaims{
		UserID:   "u-admin",
		TenantID: "t1",
		Username: "admin",
		Role:     "admin",
		Scopes:   []string{"cinema", "audit"},
	}))

	access := buildAccessContext(req, "test")

	if access.Principal.UserID != "u-admin" {
		t.Fatalf("expected user id from JWT, got %q", access.Principal.UserID)
	}
	if access.Principal.Role != "admin" {
		t.Fatalf("expected role admin, got %q", access.Principal.Role)
	}
	if access.Action != "film.read" {
		t.Fatalf("expected film.read action, got %q", access.Action)
	}
	if access.Request.Env != "test" {
		t.Fatalf("expected env test, got %q", access.Request.Env)
	}
}

func TestBuildAccessContext_FallsBackToHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/spectators/search?external_id=abc", nil)
	req.Header.Set("X-User-ID", "u-agent")
	req.Header.Set("X-Username", "agent")
	req.Header.Set("X-Role", "agent")
	req.Header.Set("X-Tenant-ID", "t2")
	req.Header.Set("X-Request-ID", "req-123")
	req.Header.Set("X-Real-IP", "10.0.0.5")

	access := buildAccessContext(req, "dev")

	if access.Principal.UserID != "u-agent" {
		t.Fatalf("expected fallback user id, got %q", access.Principal.UserID)
	}
	if access.Principal.TenantID != "t2" {
		t.Fatalf("expected fallback tenant id, got %q", access.Principal.TenantID)
	}
	if access.Request.RequestID != "req-123" {
		t.Fatalf("expected request id req-123, got %q", access.Request.RequestID)
	}
	if access.Action != "search.spectator" {
		t.Fatalf("expected search.spectator action, got %q", access.Action)
	}
}

func TestBuildAccessContext_DefaultsWithoutJWTOrHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/films", nil)

	access := buildAccessContext(req, "dev")

	if access.Principal.TenantID != "t1" {
		t.Fatalf("expected default tenant id t1, got %q", access.Principal.TenantID)
	}
	if access.Principal.UserID != "u-dev" {
		t.Fatalf("expected default user id u-dev, got %q", access.Principal.UserID)
	}
	if access.Principal.Role != "developer" {
		t.Fatalf("expected default role developer, got %q", access.Principal.Role)
	}
	if access.Request.RequestID != "http-no-request-id" {
		t.Fatalf("expected default request id http-no-request-id, got %q", access.Request.RequestID)
	}
	if access.Request.Channel != "web" {
		t.Fatalf("expected channel web, got %q", access.Request.Channel)
	}
}

func TestAccessContextMiddleware_InsertsAccessContext(t *testing.T) {
	server := &Server{
		cfg:    &config.Config{Env: "test"},
		logger: testLogger(),
	}

	handler := server.accessContextMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, ok := accessContextFromContext(r.Context())
		if !ok {
			t.Fatal("expected access context in request context")
		}
		if access.Action != "hall.read" {
			t.Fatalf("expected hall.read action, got %q", access.Action)
		}
		if access.Principal.UserID != "u-dev" {
			t.Fatalf("expected fallback user id u-dev, got %q", access.Principal.UserID)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "/halls", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", rec.Code)
	}
}
