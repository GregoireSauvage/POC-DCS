package service

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
)

// AuthService handles authentication and JWT token generation
type AuthService struct {
	userRepo repository.UserRepository
	jwtSvc   *auth.JWTService
}

// NewAuthService creates a new authentication service
func NewAuthService(userRepo repository.UserRepository, jwtSvc *auth.JWTService) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		jwtSvc:   jwtSvc,
	}
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id"` // Optional, defaults to "t1" for PoC
}

// LoginResponse represents the login response with JWT token
type LoginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds
	UserID      string `json:"user_id"`
	TenantID    string `json:"tenant_id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
}

// Login authenticates a user and returns a JWT token
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	// Default tenant for PoC
	if req.TenantID == "" {
		req.TenantID = "t1"
	}

	// Get user from database
	user, err := s.userRepo.GetByUsername(ctx, req.TenantID, req.Username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Generate JWT token
	principal := types.Principal{
		UserID:   user.ID,
		TenantID: user.TenantID,
		Username: user.Username,
		Role:     user.Role,
		Scopes:   []string{roleToScopes(user.Role)},
	}

	scopesStr := roleToScopes(user.Role)
	token, err := s.jwtSvc.GenerateToken(principal, scopesStr)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	return &LoginResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   240 * 60, // 240 minutes = 4 hours (from config)
		UserID:      user.ID,
		TenantID:    user.TenantID,
		Username:    user.Username,
		Role:        user.Role,
	}, nil
}

// roleToScopes converts a role to scopes (same logic as Python backend)
func roleToScopes(role string) string {
	switch role {
	case "admin":
		return "read write bootstrap audit"
	case "agent":
		return "read write"
	case "developer":
		return "read"
	default:
		return ""
	}
}
