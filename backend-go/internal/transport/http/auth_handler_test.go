package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// testLogger creates a no-op logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// mockUserRepository implements repository.UserRepository for testing
type mockUserRepository struct {
	user *domain.User
	err  error
}

func (m *mockUserRepository) GetByUsername(_ context.Context, _, _ string) (*domain.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

// TestHandleLogin_Success verifies successful login returns JWT token
func TestHandleLogin_Success(t *testing.T) {
	// Create password hash for "password"
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate password hash: %v", err)
	}

	userRepo := &mockUserRepository{
		user: &domain.User{
			ID:           "user-123",
			TenantID:     "t1",
			Username:     "alice",
			PasswordHash: string(hash),
			Role:         "developer",
		},
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := service.NewAuthService(userRepo, jwtSvc)

	// Create test server with auth handler
	server := &Server{
		authService: authSvc,
	}

	// Create request
	payload := map[string]string{
		"username":  "alice",
		"password":  "password",
		"tenant_id": "t1",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	server.handleLogin(w, req)

	// Assert
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var resp service.LoginResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify response fields
	if resp.AccessToken == "" {
		t.Error("Expected non-empty access_token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Expected token_type=Bearer, got %s", resp.TokenType)
	}
	if resp.UserID != "user-123" {
		t.Errorf("Expected user_id=user-123, got %s", resp.UserID)
	}
	if resp.Username != "alice" {
		t.Errorf("Expected username=alice, got %s", resp.Username)
	}
	if resp.Role != "developer" {
		t.Errorf("Expected role=developer, got %s", resp.Role)
	}

	// Verify token is valid
	claims, err := jwtSvc.ValidateToken(resp.AccessToken)
	if err != nil {
		t.Errorf("Token validation failed: %v", err)
	}
	if claims.UserID != "user-123" {
		t.Errorf("Expected claims user_id=user-123, got %s", claims.UserID)
	}
}

// TestHandleLogin_InvalidCredentials verifies 401 on wrong password
func TestHandleLogin_InvalidCredentials(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)

	userRepo := &mockUserRepository{
		user: &domain.User{
			ID:           "user-123",
			TenantID:     "t1",
			Username:     "alice",
			PasswordHash: string(hash),
			Role:         "developer",
		},
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := service.NewAuthService(userRepo, jwtSvc)

	server := &Server{
		authService: authSvc,
	}

	// Wrong password
	payload := map[string]string{
		"username": "alice",
		"password": "wrong-password",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// TestHandleLogin_UserNotFound verifies 401 on unknown user
func TestHandleLogin_UserNotFound(t *testing.T) {
	userRepo := &mockUserRepository{
		err: repository.ErrNotFound,
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := service.NewAuthService(userRepo, jwtSvc)

	server := &Server{
		authService: authSvc,
	}

	payload := map[string]string{
		"username": "unknown",
		"password": "password",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

// TestHandleLogin_InvalidJSON verifies 400 on malformed request
func TestHandleLogin_InvalidJSON(t *testing.T) {
	server := &Server{
		authService: service.NewAuthService(nil, nil),
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte("invalid-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestHandleLogin_MissingUsername verifies 400 on missing username
func TestHandleLogin_MissingUsername(t *testing.T) {
	server := &Server{
		authService: service.NewAuthService(nil, nil),
	}

	payload := map[string]string{
		"password": "password",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestHandleLogin_MethodNotAllowed verifies 405 on GET
func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	server := &Server{}

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

// TestHandleLogin_DatabaseError verifies 500 on internal error
func TestHandleLogin_DatabaseError(t *testing.T) {
	userRepo := &mockUserRepository{
		err: errors.New("database connection failed"),
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := service.NewAuthService(userRepo, jwtSvc)

	// Create a no-op logger for testing
	logger := testLogger()

	server := &Server{
		authService: authSvc,
		logger:      logger,
	}

	payload := map[string]string{
		"username": "alice",
		"password": "password",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLogin(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}
