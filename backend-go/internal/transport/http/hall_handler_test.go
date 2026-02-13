package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// ==================== GET /halls TESTS ====================

func TestGetHalls_AdminSeesAllFields(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{
		{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
	})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)
	token := adminAuthHeader(t, server)

	req := httptest.NewRequest(http.MethodGet, "/halls", nil)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var response []service.HallOutput
	json.Unmarshal(rec.Body.Bytes(), &response)

	h := response[0]
	if h.Name == nil || *h.Name != "Hall A" {
		t.Errorf("expected name='Hall A', got %v", h.Name)
	}
	if h.OwnerUserID != "u-admin" {
		t.Errorf("expected owner_user_id='u-admin', got %v", h.OwnerUserID)
	}
}

func TestGetHalls_DeveloperSeesMaskedINTERNAL(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{
		{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "user-12345678", CurrentFilmID: "film-87654321"},
	})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)

	token, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-dev", TenantID: "t1", Username: "dev", Role: "developer",
	}, "")

	req := httptest.NewRequest(http.MethodGet, "/halls", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var response []service.HallOutput
	json.Unmarshal(rec.Body.Bytes(), &response)

	h := response[0]
	// Check UUID masking (first 4 chars + ellipsis)
	if ownerStr, ok := h.OwnerUserID.(string); ok {
		if ownerStr != "user…" {
			t.Errorf("expected masked owner_user_id='user…', got %v", ownerStr)
		}
	} else {
		t.Errorf("expected masked string, got %T", h.OwnerUserID)
	}
}

func TestGetHalls_AgentSeesINTERNAL(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{
		{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-agent", CurrentFilmID: "film-1"},
	})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)

	token, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-agent", TenantID: "t1", Username: "agent", Role: "agent",
	}, "")

	req := httptest.NewRequest(http.MethodGet, "/halls", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	var response []service.HallOutput
	json.Unmarshal(rec.Body.Bytes(), &response)

	if response[0].OwnerUserID != "u-agent" {
		t.Errorf("agent should see INTERNAL unmasked, got %v", response[0].OwnerUserID)
	}
}

// TestGetHalls_NoJWT skipped - /halls uses optionalJWTMiddleware which falls back to X-headers in dev

func TestGetHalls_EmptyHalls_ReturnsEmptyArray(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)
	token := adminAuthHeader(t, server)

	req := httptest.NewRequest(http.MethodGet, "/halls", nil)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var response []service.HallOutput
	json.Unmarshal(rec.Body.Bytes(), &response)

	if response == nil || len(response) != 0 {
		t.Errorf("expected empty array, got %v", response)
	}
}

// ==================== POST /halls TESTS ====================

func TestPostHalls_AdminAllowed(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)
	token := adminAuthHeader(t, server)

	payload := map[string]interface{}{
		"name":            "Hall A",
		"owner_user_id":   "u-admin",
		"current_film_id": "film-1",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/halls", bytes.NewReader(body))
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var response service.HallOutput
	json.Unmarshal(rec.Body.Bytes(), &response)

	if response.Name == nil || *response.Name != "Hall A" {
		t.Errorf("expected name='Hall A', got %v", response.Name)
	}
	if response.SpectatorCount != 0 {
		t.Errorf("expected spectator_count=0 for new hall, got %d", response.SpectatorCount)
	}
}

func TestPostHalls_AgentAllowed(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)

	token, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-agent", TenantID: "t1", Username: "agent", Role: "agent",
	}, "")

	payload := map[string]interface{}{
		"name":            "Hall B",
		"owner_user_id":   "u-agent",
		"current_film_id": "film-2",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/halls", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
}

func TestPostHalls_DeveloperForbidden(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)

	token, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-dev", TenantID: "t1", Username: "dev", Role: "developer",
	}, "")

	payload := map[string]interface{}{
		"name":            "Hall C",
		"owner_user_id":   "u-dev",
		"current_film_id": "film-3",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/halls", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", rec.Code)
	}
}

func TestPostHalls_MissingName_Returns400(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)
	token := adminAuthHeader(t, server)

	payload := map[string]interface{}{
		"owner_user_id":   "u1",
		"current_film_id": "f1",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/halls", bytes.NewReader(body))
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestPostHalls_EmptyName_Returns400(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)
	token := adminAuthHeader(t, server)

	payload := map[string]interface{}{
		"name":            "",
		"owner_user_id":   "u1",
		"current_film_id": "f1",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/halls", bytes.NewReader(body))
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestPostHalls_InvalidJSON_Returns400(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)
	token := adminAuthHeader(t, server)

	req := httptest.NewRequest(http.MethodPost, "/halls", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestHalls_MethodDispatch(t *testing.T) {
	server := newTestServer(t)
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	server.hallService = service.NewHallService(hallRepo, server.enforcer, nil)
	token := adminAuthHeader(t, server)

	// Test unsupported method
	req := httptest.NewRequest(http.MethodPut, "/halls", nil)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for PUT, got %d", rec.Code)
	}
}
