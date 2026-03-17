package transport

import (
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

const (
	defaultTenantID    = "t1"
	defaultUserID      = "u-dev"
	defaultUsername    = "dev"
	defaultRole        = "developer"
	defaultScope       = "cinema"
	defaultPurpose     = "cinema_ops"
	defaultDeviceTrust = 0.8
)

type RequestContextDefaults struct {
	RequestIDFallback string
	Channel           string
	Purpose           string
	DeviceTrust       float64
}

func NormalizePrincipal(tenantID, userID, username, role string, scopes []string) service.Principal {
	normalizedScopes := normalizeScopes(scopes)
	if len(normalizedScopes) == 0 {
		normalizedScopes = []string{defaultScope}
	}

	return service.Principal{
		TenantID: firstNonEmpty(tenantID, defaultTenantID),
		UserID:   firstNonEmpty(userID, defaultUserID),
		Username: firstNonEmpty(username, defaultUsername),
		Role:     firstNonEmpty(role, defaultRole),
		Scopes:   normalizedScopes,
	}
}

func BuildRequestContext(requestID, clientIP, env string, defaults RequestContextDefaults) service.RequestContext {
	purpose := defaults.Purpose
	if strings.TrimSpace(purpose) == "" {
		purpose = defaultPurpose
	}
	deviceTrust := defaults.DeviceTrust
	if deviceTrust == 0 {
		deviceTrust = defaultDeviceTrust
	}

	return service.RequestContext{
		RequestID:   firstNonEmpty(requestID, defaults.RequestIDFallback),
		ClientIP:    strings.TrimSpace(clientIP),
		Channel:     strings.TrimSpace(defaults.Channel),
		Purpose:     purpose,
		DeviceTrust: deviceTrust,
		Env:         strings.TrimSpace(env),
	}
}

func normalizeScopes(scopes []string) []string {
	normalized := make([]string, 0, len(scopes))
	for _, raw := range scopes {
		for _, part := range strings.Split(raw, ",") {
			scope := strings.TrimSpace(part)
			if scope != "" {
				normalized = append(normalized, scope)
			}
		}
	}
	return normalized
}

func firstNonEmpty(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}
