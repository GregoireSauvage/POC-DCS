package service

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

// Mock UserRepository
type mockUserRepository struct {
	user *domain.User
	err  error
}

func (m *mockUserRepository) GetByUsername(ctx context.Context, tenantID, username string) (*domain.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func TestAuthService_Login_Success(t *testing.T) {
	// Create a user with hashed password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	mockRepo := &mockUserRepository{
		user: &domain.User{
			ID:           "user-1",
			TenantID:     "t1",
			Username:     "alice",
			PasswordHash: string(hashedPassword),
			Role:         "developer",
		},
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := NewAuthService(mockRepo, jwtSvc)

	req := LoginRequest{
		Username: "alice",
		Password: "password123",
		TenantID: "t1",
	}

	resp, err := authSvc.Login(context.Background(), req)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Expected TokenType Bearer, got %s", resp.TokenType)
	}
	if resp.UserID != "user-1" {
		t.Errorf("Expected UserID user-1, got %s", resp.UserID)
	}
	if resp.Role != "developer" {
		t.Errorf("Expected Role developer, got %s", resp.Role)
	}
}

func TestAuthService_Login_InvalidPassword(t *testing.T) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)

	mockRepo := &mockUserRepository{
		user: &domain.User{
			ID:           "user-1",
			TenantID:     "t1",
			Username:     "alice",
			PasswordHash: string(hashedPassword),
			Role:         "developer",
		},
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := NewAuthService(mockRepo, jwtSvc)

	req := LoginRequest{
		Username: "alice",
		Password: "wrong-password",
		TenantID: "t1",
	}

	_, err := authSvc.Login(context.Background(), req)
	if err == nil {
		t.Error("Expected login to fail with wrong password")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	mockRepo := &mockUserRepository{
		err: repository.ErrNotFound,
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := NewAuthService(mockRepo, jwtSvc)

	req := LoginRequest{
		Username: "unknown",
		Password: "password123",
		TenantID: "t1",
	}

	_, err := authSvc.Login(context.Background(), req)
	if err == nil {
		t.Error("Expected login to fail with unknown user")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthService_Login_RepositoryError(t *testing.T) {
	mockRepo := &mockUserRepository{
		err: errors.New("database timeout"),
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := NewAuthService(mockRepo, jwtSvc)

	req := LoginRequest{
		Username: "alice",
		Password: "password123",
		TenantID: "t1",
	}

	_, err := authSvc.Login(context.Background(), req)
	if err == nil {
		t.Fatal("expected login to fail when repository errors")
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected wrapped repository error, got credential error: %v", err)
	}
}

func TestAuthService_Login_DefaultTenant(t *testing.T) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	mockRepo := &mockUserRepository{
		user: &domain.User{
			ID:           "user-1",
			TenantID:     "t1",
			Username:     "alice",
			PasswordHash: string(hashedPassword),
			Role:         "developer",
		},
	}

	jwtSvc := auth.NewJWTService("test-secret", "test-issuer", "test-audience", 60)
	authSvc := NewAuthService(mockRepo, jwtSvc)

	req := LoginRequest{
		Username: "alice",
		Password: "password123",
		// TenantID omitted - should default to "t1"
	}

	resp, err := authSvc.Login(context.Background(), req)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if resp.TenantID != "t1" {
		t.Errorf("Expected TenantID t1 (default), got %s", resp.TenantID)
	}
}

func TestRoleToScopesArray(t *testing.T) {
	tests := []struct {
		role     string
		expected []string
	}{
		{"admin", []string{"*"}},         // Python parity: ["*"] for admin
		{"agent", []string{"cinema"}},    // Python parity: ["cinema"] for agent
		{"developer", []string{"cinema"}}, // Python parity: ["cinema"] for developer
		{"unknown", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			scopes := roleToScopesArray(tt.role)
			if len(scopes) != len(tt.expected) {
				t.Errorf("Expected %d scopes, got %d", len(tt.expected), len(scopes))
				return
			}
			for i, scope := range tt.expected {
				if scopes[i] != scope {
					t.Errorf("Expected scopes[%d]='%s', got '%s'", i, scope, scopes[i])
				}
			}
		})
	}
}
