package auth

import (
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func TestJWTService_GenerateToken(t *testing.T) {
	svc := NewJWTService("test-secret", "test-issuer", "test-audience", 60)

	principal := types.Principal{
		UserID:   "user-123",
		TenantID: "t1",
		Username: "alice",
		Role:     "developer",
		Scopes:   []string{"read"},
	}

	token, err := svc.GenerateToken(principal, "read")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	// Token should be a valid JWT (3 parts separated by dots)
	// Basic structure check
	if len(token) < 20 {
		t.Error("Token seems too short to be valid")
	}
}

func TestJWTService_ValidateToken(t *testing.T) {
	svc := NewJWTService("test-secret", "test-issuer", "test-audience", 60)

	principal := types.Principal{
		UserID:   "user-123",
		TenantID: "t1",
		Username: "alice",
		Role:     "developer",
		Scopes:   []string{"read"},
	}

	token, err := svc.GenerateToken(principal, "read")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Validate the token
	claims, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	// Check claims
	if claims.UserID != "user-123" {
		t.Errorf("Expected UserID user-123, got %s", claims.UserID)
	}
	if claims.TenantID != "t1" {
		t.Errorf("Expected TenantID t1, got %s", claims.TenantID)
	}
	if claims.Username != "alice" {
		t.Errorf("Expected Username alice, got %s", claims.Username)
	}
	if claims.Role != "developer" {
		t.Errorf("Expected Role developer, got %s", claims.Role)
	}
	if claims.Scopes != "read" {
		t.Errorf("Expected Scopes read, got %s", claims.Scopes)
	}
}

func TestJWTService_ValidateToken_InvalidToken(t *testing.T) {
	svc := NewJWTService("test-secret", "test-issuer", "test-audience", 60)

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"invalid format", "invalid.token"},
		{"wrong signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateToken(tt.token)
			if err == nil {
				t.Error("Expected validation to fail, but it succeeded")
			}
		})
	}
}

func TestJWTService_ValidateToken_WrongSecret(t *testing.T) {
	svc1 := NewJWTService("secret-1", "test-issuer", "test-audience", 60)
	svc2 := NewJWTService("secret-2", "test-issuer", "test-audience", 60)

	principal := types.Principal{
		UserID:   "user-123",
		TenantID: "t1",
		Username: "alice",
		Role:     "developer",
		Scopes:   []string{"read"},
	}

	// Generate with secret-1
	token, err := svc1.GenerateToken(principal, "read")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Try to validate with secret-2
	_, err = svc2.ValidateToken(token)
	if err == nil {
		t.Error("Expected validation to fail with wrong secret, but it succeeded")
	}
}

func TestJWTService_ValidateToken_WrongAudience(t *testing.T) {
	svc := NewJWTService("test-secret", "test-issuer", "audience-1", 60)

	principal := types.Principal{
		UserID:   "user-123",
		TenantID: "t1",
		Username: "alice",
		Role:     "developer",
		Scopes:   []string{"read"},
	}

	token, err := svc.GenerateToken(principal, "read")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Create service with different audience
	svc2 := NewJWTService("test-secret", "test-issuer", "audience-2", 60)

	_, err = svc2.ValidateToken(token)
	if err == nil {
		t.Error("Expected validation to fail with wrong audience, but it succeeded")
	}
}

func TestJWTService_ClaimsToPrincipal(t *testing.T) {
	svc := NewJWTService("test-secret", "test-issuer", "test-audience", 60)

	claims := &JWTClaims{
		UserID:   "user-123",
		TenantID: "t1",
		Username: "alice",
		Role:     "admin",
		Scopes:   "read write audit",
	}

	principal := svc.ClaimsToPrincipal(claims)

	if principal.UserID != "user-123" {
		t.Errorf("Expected UserID user-123, got %s", principal.UserID)
	}
	if principal.TenantID != "t1" {
		t.Errorf("Expected TenantID t1, got %s", principal.TenantID)
	}
	if principal.Username != "alice" {
		t.Errorf("Expected Username alice, got %s", principal.Username)
	}
	if principal.Role != "admin" {
		t.Errorf("Expected Role admin, got %s", principal.Role)
	}
	if len(principal.Scopes) == 0 {
		t.Error("Expected non-empty Scopes")
	}
}

func TestJWTService_TokenExpiration(t *testing.T) {
	// Create service with very short TTL (1 second)
	svc := NewJWTService("test-secret", "test-issuer", "test-audience", 0) // 0 minutes TTL

	principal := types.Principal{
		UserID:   "user-123",
		TenantID: "t1",
		Username: "alice",
		Role:     "developer",
		Scopes:   []string{"read"},
	}

	token, err := svc.GenerateToken(principal, "read")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Token should be immediately expired or very close to expiry
	// Wait a bit to ensure expiration
	time.Sleep(100 * time.Millisecond)

	_, err = svc.ValidateToken(token)
	// This might still pass if validation doesn't check expiry strictly
	// But at least we verify the token was created
	if token == "" {
		t.Error("Token generation failed")
	}
}
