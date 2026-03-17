package auth

import (
	"fmt"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTSubject represents the subject data encoded in JWT tokens.
type JWTSubject struct {
	UserID   string
	TenantID string
	Username string
	Role     string
	Scopes   []string
}

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	UserID   string   `json:"sub"`
	TenantID string   `json:"tenant_id"`
	Username string   `json:"username"`
	Role     string   `json:"role"`
	Scopes   []string `json:"scopes,omitempty"`
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

// GenerateToken creates a new JWT token for a user.
// It accepts JWTSubject and principal-like structs exposed by the backend tests.
func (j *JWTService) GenerateToken(subject any) (string, error) {
	normalized, err := normalizeSubject(subject)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := JWTClaims{
		UserID:   normalized.UserID,
		TenantID: normalized.TenantID,
		Username: normalized.Username,
		Role:     normalized.Role,
		Scopes:   normalized.Scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
			Subject:   normalized.UserID,
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
	if claims.Issuer != j.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	return claims, nil
}

// ClaimsToSubject converts JWT claims to a JWTSubject.
func (j *JWTService) ClaimsToSubject(claims *JWTClaims) JWTSubject {
	return JWTSubject{
		UserID:   claims.UserID,
		TenantID: claims.TenantID,
		Username: claims.Username,
		Role:     claims.Role,
		Scopes:   claims.Scopes,
	}
}

func normalizeSubject(subject any) (JWTSubject, error) {
	switch s := subject.(type) {
	case JWTSubject:
		return s, nil
	case *JWTSubject:
		if s == nil {
			return JWTSubject{}, fmt.Errorf("nil JWT subject")
		}
		return *s, nil
	}

	v := reflect.ValueOf(subject)
	if !v.IsValid() {
		return JWTSubject{}, fmt.Errorf("invalid JWT subject")
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return JWTSubject{}, fmt.Errorf("nil JWT subject")
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return JWTSubject{}, fmt.Errorf("unsupported JWT subject type %T", subject)
	}

	userID, err := extractStringField(v, "UserID")
	if err != nil {
		return JWTSubject{}, err
	}
	tenantID, err := extractStringField(v, "TenantID")
	if err != nil {
		return JWTSubject{}, err
	}
	username, err := extractStringField(v, "Username")
	if err != nil {
		return JWTSubject{}, err
	}
	role, err := extractStringField(v, "Role")
	if err != nil {
		return JWTSubject{}, err
	}
	scopes, err := extractStringSliceField(v, "Scopes")
	if err != nil {
		return JWTSubject{}, err
	}

	return JWTSubject{
		UserID:   userID,
		TenantID: tenantID,
		Username: username,
		Role:     role,
		Scopes:   scopes,
	}, nil
}

func extractStringField(v reflect.Value, name string) (string, error) {
	field := v.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String {
		return "", fmt.Errorf("JWT subject missing string field %q", name)
	}
	return field.String(), nil
}

func extractStringSliceField(v reflect.Value, name string) ([]string, error) {
	field := v.FieldByName(name)
	if !field.IsValid() {
		return nil, fmt.Errorf("JWT subject missing slice field %q", name)
	}
	if field.Kind() != reflect.Slice {
		return nil, fmt.Errorf("JWT subject field %q is not a slice", name)
	}

	out := make([]string, 0, field.Len())
	for i := 0; i < field.Len(); i++ {
		item := field.Index(i)
		if item.Kind() != reflect.String {
			return nil, fmt.Errorf("JWT subject field %q contains non-string values", name)
		}
		out = append(out, item.String())
	}
	return out, nil
}
