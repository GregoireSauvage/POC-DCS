package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// POST /spectators - Create Spectator Tests
// ============================================================================

// TestHandleCreateSpectator_Success_AdminDecrypted verifies admin can create and sees all decrypted
func TestHandleCreateSpectator_Success_AdminDecrypted(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"hall_id":     "hall-1",
		"name":        "John Doe",
		"age":         25,
		"external_id": "ABC123",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
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

	// Verify response structure
	if resp["id"] == nil || resp["id"] == "" {
		t.Error("Expected non-empty id")
	}
	if resp["hall_id"] != "hall-1" {
		t.Errorf("Expected hall_id=hall-1, got %v", resp["hall_id"])
	}
	// Admin sees all decrypted
	if resp["name"] != "John Doe" {
		t.Errorf("Expected name=John Doe (decrypted), got %v", resp["name"])
	}
	if resp["age"] != float64(25) {
		t.Errorf("Expected age=25 (decrypted), got %v", resp["age"])
	}
	if resp["external_id"] != "ABC123" {
		t.Errorf("Expected external_id=ABC123 (decrypted), got %v", resp["external_id"])
	}
}

// TestHandleCreateSpectator_Success_AgentMaskedPII verifies agent sees age decrypted, PII masked
func TestHandleCreateSpectator_Success_AgentMaskedPII(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"hall_id":     "hall-1",
		"name":        "Jane Smith",
		"age":         30,
		"external_id": "XYZ789",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	req.Header.Set("X-Role", "agent")
	req.Header.Set("X-Tenant-ID", "t1")
	req.Header.Set("X-User-ID", "agent-1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	// Agent sees age decrypted (SENSITIVE), PII masked
	if resp["age"] != float64(30) {
		t.Errorf("Expected age=30 (decrypted for agent), got %v", resp["age"])
	}
	if resp["name"] != "J***" {
		t.Errorf("Expected name=J*** (masked for agent), got %v", resp["name"])
	}
	if resp["external_id"] != "X***" {
		t.Errorf("Expected external_id=X*** (masked for agent), got %v", resp["external_id"])
	}

	// Agent sees masked spectator ID (not admin)
	spectatorID, ok := resp["id"].(string)
	if !ok {
		t.Error("Expected id to be string")
	}
	// Check for masking pattern (should contain ellipsis)
	if !strings.Contains(spectatorID, "…") {
		t.Errorf("Expected masked ID with ellipsis (e.g., 550e…), got %v", spectatorID)
	}
}

// TestHandleCreateSpectator_Forbidden_Developer verifies developer is denied (403)
func TestHandleCreateSpectator_Forbidden_Developer(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"hall_id":     "hall-1",
		"name":        "Test User",
		"age":         20,
		"external_id": "TEST123",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	req.Header.Set("X-Role", "developer")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for developer, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// TestHandleCreateSpectator_MissingHallID verifies 422 when hall_id missing
func TestHandleCreateSpectator_MissingHallID(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		// hall_id omitted
		"name":        "Test",
		"age":         20,
		"external_id": "TEST",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected status 422 when hall_id missing, got %d", w.Code)
	}
}

// TestHandleCreateSpectator_MissingName verifies 422 when name missing
func TestHandleCreateSpectator_MissingName(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"hall_id": "hall-1",
		// name omitted
		"age":         20,
		"external_id": "TEST",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected status 422 when name missing, got %d", w.Code)
	}
}

// TestHandleCreateSpectator_MissingExternalID verifies 422 when external_id missing
func TestHandleCreateSpectator_MissingExternalID(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"hall_id": "hall-1",
		"name":    "Test",
		"age":     20,
		// external_id omitted
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected status 422 when external_id missing, got %d", w.Code)
	}
}

// TestHandleCreateSpectator_HallNotFound verifies 404 when hall doesn't exist
func TestHandleCreateSpectator_HallNotFound(t *testing.T) {
	server := newTestServer(t)

	payload := map[string]interface{}{
		"hall_id":     "nonexistent-hall",
		"name":        "Test",
		"age":         20,
		"external_id": "TEST",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 when hall not found, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// TestHandleCreateSpectator_InvalidJSON verifies 400 for malformed JSON
func TestHandleCreateSpectator_InvalidJSON(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader([]byte("{invalid json")))
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid JSON, got %d", w.Code)
	}
}

// ============================================================================
// GET /spectators/search - Search Spectators Tests
// ============================================================================

// TestHandleSearchSpectators_Success_AdminFindsMultiple verifies admin can search and sees all decrypted
func TestHandleSearchSpectators_Success_AdminFindsMultiple(t *testing.T) {
	server := newTestServer(t)

	// First, create two spectators with same external_id
	createPayload := map[string]interface{}{
		"hall_id":     "hall-1",
		"name":        "Alice",
		"age":         25,
		"external_id": "SHARED123",
	}
	body, _ := json.Marshal(createPayload)
	createReq := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	createReq.Header.Set("X-Role", "admin")
	createReq.Header.Set("X-Tenant-ID", "t1")
	server.Handler().ServeHTTP(httptest.NewRecorder(), createReq)

	// Create second with same external_id
	createPayload2 := map[string]interface{}{
		"hall_id":     "hall-2",
		"name":        "Bob",
		"age":         30,
		"external_id": "SHARED123",
	}
	body2, _ := json.Marshal(createPayload2)
	createReq2 := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body2))
	createReq2.Header.Set("X-Role", "admin")
	createReq2.Header.Set("X-Tenant-ID", "t1")
	server.Handler().ServeHTTP(httptest.NewRecorder(), createReq2)

	// Now search
	searchReq := httptest.NewRequest(http.MethodGet, "/spectators/search?external_id=SHARED123", nil)
	searchReq.Header.Set("X-Role", "admin")
	searchReq.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, searchReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var results []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&results); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(results) < 1 {
		t.Errorf("Expected at least 1 result, got %d", len(results))
	}

	// Verify admin sees decrypted fields
	for _, result := range results {
		if result["external_id"] != "SHARED123" {
			t.Errorf("Expected external_id=SHARED123 (decrypted), got %v", result["external_id"])
		}
	}
}

// TestHandleSearchSpectators_Success_AgentMaskedPII verifies agent sees masked PII
func TestHandleSearchSpectators_Success_AgentMaskedPII(t *testing.T) {
	server := newTestServer(t)

	// Create spectator
	createPayload := map[string]interface{}{
		"hall_id":     "hall-1",
		"name":        "Charlie",
		"age":         28,
		"external_id": "AGENT123",
	}
	body, _ := json.Marshal(createPayload)
	createReq := httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(body))
	createReq.Header.Set("X-Role", "admin") // Create as admin
	createReq.Header.Set("X-Tenant-ID", "t1")
	server.Handler().ServeHTTP(httptest.NewRecorder(), createReq)

	// Search as agent
	searchReq := httptest.NewRequest(http.MethodGet, "/spectators/search?external_id=AGENT123", nil)
	searchReq.Header.Set("X-Role", "agent")
	searchReq.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, searchReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var results []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&results)

	if len(results) > 0 {
		result := results[0]
		// Agent sees age decrypted, PII masked
		if result["age"] != float64(28) {
			t.Errorf("Expected age=28 (decrypted), got %v", result["age"])
		}
		if result["name"] != "C***" {
			t.Errorf("Expected name=C*** (masked), got %v", result["name"])
		}
		if result["external_id"] != "A***" {
			t.Errorf("Expected external_id=A*** (masked), got %v", result["external_id"])
		}
	}
}

// TestHandleSearchSpectators_Forbidden_Developer verifies developer is denied (403)
func TestHandleSearchSpectators_Forbidden_Developer(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/spectators/search?external_id=TEST123", nil)
	req.Header.Set("X-Role", "developer")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for developer, got %d", w.Code)
	}
}

// TestHandleSearchSpectators_MissingExternalID verifies 422 when external_id query param missing
func TestHandleSearchSpectators_MissingExternalID(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/spectators/search", nil) // No query param
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("Expected status 422 when external_id missing, got %d", w.Code)
	}
}

// TestHandleSearchSpectators_NoResults verifies empty array when no matches
func TestHandleSearchSpectators_NoResults(t *testing.T) {
	server := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/spectators/search?external_id=NOTFOUND999", nil)
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 even with no results, got %d", w.Code)
	}

	var results []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&results)

	if len(results) != 0 {
		t.Errorf("Expected empty array, got %d results", len(results))
	}
}
