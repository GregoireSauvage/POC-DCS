package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleCreateFilm_Success_AdminDecrypted verifies admin can create and sees decrypted response
func TestHandleCreateFilm_Success_AdminDecrypted(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"title":        "Matrix",
		"time_elapsed": 136,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	req.Header.Set("X-User-ID", "admin-1")
	req.Header.Set("X-Username", "admin")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["id"] == nil || resp["id"] == "" {
		t.Error("Expected non-empty id")
	}
	if resp["title"] != "Matrix" {
		t.Errorf("Expected title=Matrix, got %v", resp["title"])
	}
	// Admin sees decrypted time_elapsed (integer)
	if resp["time_elapsed"] != float64(136) {
		t.Errorf("Expected time_elapsed=136 (decrypted), got %v", resp["time_elapsed"])
	}
}

// TestHandleCreateFilm_Success_AgentDecrypted verifies agent can create and sees decrypted response
func TestHandleCreateFilm_Success_AgentDecrypted(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"title":        "Inception",
		"time_elapsed": 148,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Role", "agent")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	// Agent sees decrypted time_elapsed (SENSITIVE → decrypt for agent)
	if resp["time_elapsed"] != float64(148) {
		t.Errorf("Expected decrypted time_elapsed=148 for agent, got %v", resp["time_elapsed"])
	}
}

// TestHandleCreateFilm_DefaultTimeElapsed verifies time_elapsed defaults to 0 when omitted
func TestHandleCreateFilm_DefaultTimeElapsed(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"title": "Test Film",
		// time_elapsed omitted (should default to 0)
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["time_elapsed"] != float64(0) {
		t.Errorf("Expected time_elapsed=0 (default), got %v", resp["time_elapsed"])
	}
}

// TestHandleCreateFilm_Forbidden_Developer verifies developer is denied (403)
func TestHandleCreateFilm_Forbidden_Developer(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"title":        "Test",
		"time_elapsed": 100,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("X-Role", "developer")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for developer, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// TestHandleCreateFilm_BadRequest_MissingTitle verifies 400 when title is missing
func TestHandleCreateFilm_BadRequest_MissingTitle(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"time_elapsed": 100,
		// title missing
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing title, got %d", w.Code)
	}
}

// TestHandleCreateFilm_BadRequest_EmptyTitle verifies 400 when title is empty string
func TestHandleCreateFilm_BadRequest_EmptyTitle(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"title":        "",
		"time_elapsed": 100,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty title, got %d", w.Code)
	}
}

// TestHandleCreateFilm_BadRequest_NegativeTimeElapsed verifies 400 when time_elapsed < 0
func TestHandleCreateFilm_BadRequest_NegativeTimeElapsed(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"title":        "Test",
		"time_elapsed": -10,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for negative time_elapsed, got %d", w.Code)
	}
}

// TestHandleCreateFilm_BadRequest_InvalidJSON verifies 400 for malformed JSON
func TestHandleCreateFilm_BadRequest_InvalidJSON(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader([]byte("{invalid json")))
	req.Header.Set("X-Role", "admin")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid JSON, got %d", w.Code)
	}
}

// TestHandleFilms_MethodDispatch verifies GET/POST routing
func TestHandleFilms_MethodDispatch(t *testing.T) {
	server := newTestServer(t)

	// GET should work (list films)
	req := httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for GET /films, got %d", w.Code)
	}

	// POST should work (create film)
	payload := map[string]interface{}{
		"title":        "New Film",
		"time_elapsed": 120,
	}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for POST /films, got %d", w.Code)
	}

	// Other methods should return 405
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req = httptest.NewRequest(method, "/films", nil)
		w = httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 for %s /films, got %d", method, w.Code)
		}
	}
}
