package http

import (
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type contextKey string

const jwtClaimsKey contextKey = "jwt_claims"

func principalFromRequest(r *nethttp.Request) service.Principal {
	if access, ok := accessContextFromContext(r.Context()); ok {
		return access.Principal
	}

	return buildPrincipal(r)
}

func buildPrincipal(r *nethttp.Request) service.Principal {
	if claims, ok := r.Context().Value(jwtClaimsKey).(*auth.JWTClaims); ok {
		return service.Principal{
			TenantID: claims.TenantID,
			UserID:   claims.UserID,
			Username: claims.Username,
			Role:     claims.Role,
			Scopes:   claims.Scopes, // Scopes are already []string, use directly
		}
	}

	return service.Principal{
		TenantID: readHeaderOrDefault(r, "X-Tenant-ID", "t1"),
		UserID:   readHeaderOrDefault(r, "X-User-ID", "u-dev"),
		Username: readHeaderOrDefault(r, "X-Username", "dev"),
		Role:     readHeaderOrDefault(r, "X-Role", "developer"),
		Scopes:   []string{"cinema"}, // Default scope for dev/testing
	}
}

func requestContextFromRequest(r *nethttp.Request, env string) service.RequestContext {
	if access, ok := accessContextFromContext(r.Context()); ok {
		return access.Request
	}

	return buildRequestContext(r, env)
}

func buildRequestContext(r *nethttp.Request, env string) service.RequestContext {
	return service.RequestContext{
		RequestID:   readHeaderOrDefault(r, "X-Request-ID", "http-no-request-id"),
		ClientIP:    readHeaderOrDefault(r, "X-Real-IP", r.RemoteAddr),
		Channel:     "web",
		Purpose:     "cinema_ops",
		DeviceTrust: 0.8,
		Env:         env,
	}
}

func readHeaderOrDefault(r *nethttp.Request, key, fallback string) string {
	val := strings.TrimSpace(r.Header.Get(key))
	if val == "" {
		return fallback
	}
	return val
}

func setPerfHeaders(w nethttp.ResponseWriter, pctx *perf.Context) {
	if pctx == nil {
		return
	}
	w.Header().Set("x-perf-total-ms", fmt.Sprintf("%.3f", pctx.TotalMS()))
	for key, value := range pctx.Metrics() {
		w.Header().Set("x-perf-"+strings.ReplaceAll(key, "_", "-"), fmt.Sprintf("%.3f", value))
	}
}

func writeError(w nethttp.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]interface{}{"detail": message})
}

func writeJSON(w nethttp.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
