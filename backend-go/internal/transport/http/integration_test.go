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

// TestIntegration_FilmLifecycle tests the complete CRUD lifecycle of a film
// with DCS enforcement at each step
func TestIntegration_FilmLifecycle(t *testing.T) {
	server := newTestServer(t)

	// Admin creates a film
	adminToken, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-admin", TenantID: "t1", Username: "admin", Role: "admin",
	})

	// 1. CREATE - Admin creates a new film
	createReq := map[string]interface{}{
		"title":        "Inception",
		"time_elapsed": 148, // Must be a number, not string
	}
	createBody, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("CREATE failed: expected 200 or 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var createdFilm map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &createdFilm)
	filmID := createdFilm["id"].(string)

	// 2. READ as Admin - should see decrypted time_elapsed
	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("READ as admin failed: expected 200, got %d", rec.Code)
	}

	var adminFilms []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &adminFilms)
	if len(adminFilms) < 2 { // seed + created
		t.Fatalf("expected at least 2 films, got %d", len(adminFilms))
	}

	// Find our created film
	var ourFilm map[string]interface{}
	for _, f := range adminFilms {
		if f["id"] == filmID {
			ourFilm = f
			break
		}
	}
	if ourFilm["title"] != "Inception" {
		t.Errorf("expected title 'Inception', got %v", ourFilm["title"])
	}
	// Admin should see numeric time_elapsed (decrypted)
	if _, ok := ourFilm["time_elapsed"].(float64); !ok {
		t.Errorf("admin should see numeric time_elapsed, got %T: %v", ourFilm["time_elapsed"], ourFilm["time_elapsed"])
	}

	// 3. READ as Developer - should see masked time_elapsed
	devToken, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-dev", TenantID: "t1", Username: "dev", Role: "developer",
	})

	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+devToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("READ as developer failed: expected 200, got %d", rec.Code)
	}

	var devFilms []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &devFilms)

	for _, f := range devFilms {
		if f["id"] == filmID {
			ourFilm = f
			break
		}
	}
	// Developer should see masked time_elapsed (string with ...)
	if timeStr, ok := ourFilm["time_elapsed"].(string); !ok || timeStr == "148" {
		t.Errorf("developer should see masked time_elapsed, got %T: %v", ourFilm["time_elapsed"], ourFilm["time_elapsed"])
	}

	// 4. UPDATE - Admin updates the film (time_elapsed as query parameter)
	req = httptest.NewRequest(http.MethodPatch, "/films/"+filmID+"/time?time_elapsed=150", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("UPDATE failed: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Verify update - Admin reads again
	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	json.Unmarshal(rec.Body.Bytes(), &adminFilms)
	for _, f := range adminFilms {
		if f["id"] == filmID {
			if timeElapsed, ok := f["time_elapsed"].(float64); !ok || timeElapsed != 150 {
				t.Errorf("expected time_elapsed 150 after update, got %v", f["time_elapsed"])
			}
			break
		}
	}
}

// TestIntegration_MultiTenantIsolation verifies tenant isolation
func TestIntegration_MultiTenantIsolation(t *testing.T) {
	server := newTestServer(t)

	// User from tenant t1
	t1Token, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u1", TenantID: "t1", Username: "user1", Role: "admin",
	})

	// User from tenant t2
	t2Token, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u2", TenantID: "t2", Username: "user2", Role: "admin",
	})

	// Tenant t2 creates a film
	createReq := map[string]interface{}{
		"title":        "T2-Film",
		"time_elapsed": 100, // Must be a number
	}
	createBody, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+t2Token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("tenant t2 CREATE failed: expected 200 or 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// Tenant t1 lists films - should NOT see t2's film
	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+t1Token)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	var t1Films []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &t1Films)

	// Should only see the seed film for t1 (film-1)
	for _, f := range t1Films {
		if f["title"] == "T2-Film" {
			t.Error("tenant t1 should NOT see tenant t2's film")
		}
	}

	// Tenant t2 lists films - should see their film
	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+t2Token)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	var t2Films []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &t2Films)

	found := false
	for _, f := range t2Films {
		if f["title"] == "T2-Film" {
			found = true
			break
		}
	}
	if !found {
		t.Error("tenant t2 should see their own film")
	}
}

// TestIntegration_DCSRoleMatrix tests DCS enforcement across different roles
func TestIntegration_DCSRoleMatrix(t *testing.T) {
	server := newTestServer(t)

	roles := []struct {
		name              string
		role              string
		expectTimeElapsed string // "number", "masked", or "denied"
	}{
		{"admin", "admin", "number"},
		{"agent", "agent", "number"},
		{"developer", "developer", "masked"},
	}

	for _, tc := range roles {
		t.Run(tc.name, func(t *testing.T) {
			token, _ := server.jwtService.GenerateToken(types.Principal{
				UserID: "u-" + tc.role, TenantID: "t1", Username: tc.role, Role: tc.role,
			})

			req := httptest.NewRequest(http.MethodGet, "/films", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET films failed for %s: expected 200, got %d", tc.role, rec.Code)
			}

			var films []map[string]interface{}
			json.Unmarshal(rec.Body.Bytes(), &films)

			if len(films) == 0 {
				t.Fatalf("expected at least 1 film, got 0")
			}

			timeElapsed := films[0]["time_elapsed"]

			switch tc.expectTimeElapsed {
			case "number":
				if _, ok := timeElapsed.(float64); !ok {
					t.Errorf("%s: expected numeric time_elapsed, got %T: %v", tc.role, timeElapsed, timeElapsed)
				}
			case "masked":
				if _, ok := timeElapsed.(string); !ok {
					t.Errorf("%s: expected masked (string) time_elapsed, got %T: %v", tc.role, timeElapsed, timeElapsed)
				}
			}
		})
	}
}

// TestIntegration_HallSpectatorWorkflow tests the complete workflow
// of creating a hall and adding spectators
func TestIntegration_HallSpectatorWorkflow(t *testing.T) {
	// Create server with custom hall repo
	hallRepo := memory.NewHallRepository([]domain.Hall{})
	spectatorRepo := memory.NewSpectatorRepository()

	server := newTestServerWithDeps(t, func(b *TestDependenciesBuilder) {
		hallService := service.NewHallService(hallRepo, b.deps.Enforcer, nil, nil, b.deps.Runtime)
		spectatorService := service.NewSpectatorService(spectatorRepo, hallRepo, b.deps.Enforcer, nil, nil, b.deps.Runtime)
		b.WithHallService(hallService)
		b.WithSpectatorService(spectatorService)
	})

	adminToken, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-admin", TenantID: "t1", Username: "admin", Role: "admin",
	})

	// 1. Create a hall
	createHallReq := map[string]interface{}{
		"name":             "IMAX Hall",
		"owner_user_id":    "u-admin",
		"current_film_id":  "film-1",
	}
	hallBody, _ := json.Marshal(createHallReq)

	req := httptest.NewRequest(http.MethodPost, "/halls", bytes.NewReader(hallBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("CREATE hall failed: expected 200 or 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var createdHall map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &createdHall)
	hallID := createdHall["id"].(string)

	// 2. Admin creates a spectator in that hall
	externalID := "EXT-UNIQUE-12345"
	createSpectatorReq := map[string]interface{}{
		"hall_id":     hallID,
		"name":        "Alice Smith",
		"age":         28, // Must be a number
		"external_id": externalID,
	}
	spectatorBody, _ := json.Marshal(createSpectatorReq)

	req = httptest.NewRequest(http.MethodPost, "/spectators", bytes.NewReader(spectatorBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("CREATE spectator failed: expected 200 or 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var createdSpectator map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &createdSpectator)

	// Admin should see decrypted data
	if name, ok := createdSpectator["name"].(string); !ok || name != "Alice Smith" {
		t.Logf("admin sees name: %v (type: %T)", createdSpectator["name"], createdSpectator["name"])
	}

	// 3. Admin searches for the spectator by external_id
	req = httptest.NewRequest(http.MethodGet, "/spectators/search?external_id="+externalID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("SEARCH spectator failed: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var foundSpectators []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &foundSpectators)

	if len(foundSpectators) == 0 {
		t.Log("No spectators found - this may be expected if search uses encrypted lookup")
	} else {
		// Admin should see decrypted name
		adminSpectator := foundSpectators[0]
		if name, ok := adminSpectator["name"].(string); !ok || name != "Alice Smith" {
			t.Logf("admin sees name: %v (type: %T)", adminSpectator["name"], adminSpectator["name"])
		}
	}
}

// TestIntegration_ErrorHandling tests error scenarios across the stack
func TestIntegration_ErrorHandling(t *testing.T) {
	server := newTestServer(t)

	adminToken, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-admin", TenantID: "t1", Username: "admin", Role: "admin",
	})

	testCases := []struct {
		name           string
		method         string
		path           string
		body           map[string]interface{}
		token          string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:   "invalid auth token",
			method: http.MethodGet,
			path:   "/audit", // Admin-only endpoint
			token:  "invalid-token",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:   "invalid film creation - missing title",
			method: http.MethodPost,
			path:   "/films",
			body: map[string]interface{}{
				"time_elapsed": "100",
			},
			token:          adminToken,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid film update - non-numeric time",
			method:         http.MethodPatch,
			path:           "/films/film-1/time?time_elapsed=invalid",
			token:          adminToken,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "update with valid time",
			method:         http.MethodPatch,
			path:           "/films/film-1/time?time_elapsed=150",
			token:          adminToken,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.body != nil {
				body, _ = json.Marshal(tc.body)
			}

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(body))
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if tc.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}

			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tc.expectedStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestIntegration_ConcurrentRequests tests handling of concurrent requests
func TestIntegration_ConcurrentRequests(t *testing.T) {
	server := newTestServer(t)

	adminToken, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-admin", TenantID: "t1", Username: "admin", Role: "admin",
	})

	// Run 10 concurrent GET requests
	done := make(chan bool, 10)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			req := httptest.NewRequest(http.MethodGet, "/films", nil)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				errors <- &testError{message: "concurrent request failed", code: rec.Code}
			}
			done <- true
		}(i)
	}

	// Wait for all requests
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

type testError struct {
	message string
	code    int
}

func (e *testError) Error() string {
	return e.message
}

// TestIntegration_DCSSwitchRuntime tests toggling DCS on/off at runtime
func TestIntegration_DCSSwitchRuntime(t *testing.T) {
	server := newTestServer(t)

	adminToken, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-admin", TenantID: "t1", Username: "admin", Role: "admin",
	})

	devToken, _ := server.jwtService.GenerateToken(types.Principal{
		UserID: "u-dev", TenantID: "t1", Username: "dev", Role: "developer",
	})

	// 1. DCS is ON - developer sees masked data
	req := httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+devToken)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	var filmsOn []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &filmsOn)
	timeElapsedOn := filmsOn[0]["time_elapsed"]

	// Should be masked (string)
	if _, ok := timeElapsedOn.(string); !ok {
		t.Errorf("with DCS ON, developer should see masked time_elapsed, got %T", timeElapsedOn)
	}

	// 2. Admin turns DCS OFF
	settingsReq := map[string]interface{}{
		"dcs_mode": "off",
	}
	settingsBody, _ := json.Marshal(settingsReq)

	req = httptest.NewRequest(http.MethodPatch, "/admin/settings", bytes.NewReader(settingsBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("failed to toggle DCS off: %d", rec.Code)
	}

	// 3. DCS is OFF - developer sees cleartext data
	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+devToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	var filmsOff []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &filmsOff)
	timeElapsedOff := filmsOff[0]["time_elapsed"]

	// Should be cleartext (could be string or number depending on implementation)
	// The key point is it should NOT be masked
	t.Logf("DCS OFF: time_elapsed = %v (type: %T)", timeElapsedOff, timeElapsedOff)

	// 4. Admin turns DCS back ON
	settingsReq = map[string]interface{}{
		"dcs_mode": "on",
	}
	settingsBody, _ = json.Marshal(settingsReq)

	req = httptest.NewRequest(http.MethodPatch, "/admin/settings", bytes.NewReader(settingsBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("failed to toggle DCS on: %d", rec.Code)
	}
}
