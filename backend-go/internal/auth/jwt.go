package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	UserID   string `json:"sub"`
	TenantID string `json:"tenant_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Scopes   string `json:"scopes,omitempty"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token generation and validation
type JWTService struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
}

// NewJWTService creates a new JWT service
func NewJWTService(secret, issuer, audience string, ttlMinutes int) *JWTService {
	return &JWTService{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
		ttl:      time.Duration(ttlMinutes) * time.Minute,
	}
}

// GenerateToken creates a new JWT token for a user
func (j *JWTService) GenerateToken(principal types.Principal, scopesStr string) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:   principal.UserID,
		TenantID: principal.TenantID,
		Username: principal.Username,
		Role:     principal.Role,
		Scopes:   scopesStr,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
			Subject:   principal.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(j.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// ValidateToken validates a JWT token and returns the claims
func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify audience - check if our audience is in the token's audience list
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == j.audience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return nil, fmt.Errorf("invalid audience")
	}

	// Verify issuer
	if claims.Issuer != j.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	return claims, nil
}

// ClaimsToPrincipal converts JWT claims to a Principal
func (j *JWTService) ClaimsToPrincipal(claims *JWTClaims) types.Principal {
	// Convert scopes string to array
	var scopes []string
	if claims.Scopes != "" {
		// Split by space (e.g., "read write" -> ["read", "write"])
		scopes = []string{claims.Scopes} // For now, store as single string in array
	}

	return types.Principal{
		UserID:   claims.UserID,
		TenantID: claims.TenantID,
		Username: claims.Username,
		Role:     claims.Role,
		Scopes:   scopes,
	}
}
