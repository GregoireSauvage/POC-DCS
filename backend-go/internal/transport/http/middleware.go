package http

import (
	"context"
	"log/slog"
	nethttp "net/http"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
)

func (s *Server) accessContextMiddleware(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		access := buildAccessContext(r, s.cfg.Env)
		s.logger.Debug("http access context built",
			slog.String("request_id", access.Request.RequestID),
			slog.String("tenant_id", access.Principal.TenantID),
			slog.String("user_id", access.Principal.UserID),
			slog.String("role", access.Principal.Role),
			slog.String("action", string(access.Action)),
			slog.String("channel", access.Request.Channel),
		)
		ctx := withAccessContext(r.Context(), access)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// jwtMiddleware validates JWT token and rejects requests without valid token
func (s *Server) jwtMiddleware(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, nethttp.StatusUnauthorized, "missing authorization header")
			return
		}

		// Parse "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeError(w, nethttp.StatusUnauthorized, "invalid authorization header format")
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := s.jwtService.ValidateToken(tokenString)
		if err != nil {
			s.logger.Debug("jwt validation failed", slog.String("error", err.Error()))
			writeError(w, nethttp.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Store claims in context
		s.logger.Debug("jwt validated",
			slog.String("user_id", claims.UserID),
			slog.String("username", claims.Username),
			slog.String("role", claims.Role),
			slog.String("tenant_id", claims.TenantID),
			slog.String("path", r.URL.Path),
		)
		ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// adminMiddleware requires valid JWT token with admin role
func (s *Server) adminMiddleware(next nethttp.Handler) nethttp.Handler {
	return s.jwtMiddleware(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Extract claims from context (set by jwtMiddleware)
		claims, ok := r.Context().Value(jwtClaimsKey).(*auth.JWTClaims)
		if !ok {
			// Should not happen if jwtMiddleware is working correctly
			writeError(w, nethttp.StatusUnauthorized, "missing authentication")
			return
		}

		// Check if user has admin role
		if claims.Role != "admin" {
			s.logger.Warn("non-admin user attempted to access admin endpoint",
				slog.String("user_id", claims.UserID),
				slog.String("username", claims.Username),
				slog.String("role", claims.Role),
				slog.String("path", r.URL.Path),
			)
			writeError(w, nethttp.StatusForbidden, "admin role required")
			return
		}

		s.logger.Debug("admin access granted",
			slog.String("user_id", claims.UserID),
			slog.String("username", claims.Username),
			slog.String("role", claims.Role),
			slog.String("path", r.URL.Path),
		)

		next.ServeHTTP(w, r)
	}))
}

// optionalJWTMiddleware tries to extract JWT but falls back to X-headers if not present (backward compatibility)
func (s *Server) optionalJWTMiddleware(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Try to extract JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				// Validate token
				claims, err := s.jwtService.ValidateToken(parts[1])
				if err == nil {
					// Valid JWT - store in context
					ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Invalid JWT - return 401
				s.logger.Debug("jwt validation failed", slog.String("error", err.Error()))
				writeError(w, nethttp.StatusUnauthorized, "invalid or expired token")
				return
			}
		}

		// No JWT or invalid format - fallback to X-headers for dev/testing
		next.ServeHTTP(w, r)
	})
}
