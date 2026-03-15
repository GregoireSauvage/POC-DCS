package grpc

import (
	"context"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	"google.golang.org/grpc/metadata"
)

func withAccessContext(ctx context.Context, access service.AccessContext) context.Context {
	return service.WithAccessContext(ctx, access)
}

func buildAccessContext(ctx context.Context, fullMethod, env string) service.AccessContext {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	return service.AccessContext{
		Principal: service.Principal{
			TenantID: metadataValue(md, "x-tenant-id", "t1"),
			UserID:   metadataValue(md, "x-user-id", "u-dev"),
			Username: metadataValue(md, "x-username", "dev"),
			Role:     metadataValue(md, "x-role", "developer"),
			Scopes:   metadataScopes(md),
		},
		Request: service.RequestContext{
			RequestID:   metadataValue(md, "x-request-id", "grpc-no-request-id"),
			ClientIP:    metadataValue(md, "x-real-ip", ""),
			Channel:     "grpc",
			Purpose:     "cinema_ops",
			DeviceTrust: 0.8,
			Env:         env,
		},
		Action: resolveGRPCAction(fullMethod),
	}
}

func resolveGRPCAction(fullMethod string) service.Action {
	method := strings.ToLower(strings.TrimSpace(fullMethod))

	switch {
	case method == "/grpc.health.v1.health/check", method == "/grpc.health.v1.health/watch":
		return service.ActionBootstrap
	case strings.Contains(method, "audit"):
		return service.ActionAuditRead
	case strings.Contains(method, "perf"):
		return service.ActionPerfRead
	case strings.Contains(method, "film") && strings.Contains(method, "update") && strings.Contains(method, "time"):
		return service.ActionFilmUpdateTime
	case strings.Contains(method, "film") && strings.Contains(method, "create"):
		return service.ActionFilmCreate
	case strings.Contains(method, "film") && (strings.Contains(method, "list") || strings.Contains(method, "get") || strings.Contains(method, "read")):
		return service.ActionFilmRead
	case strings.Contains(method, "hall") && strings.Contains(method, "create"):
		return service.ActionHallCreate
	case strings.Contains(method, "hall") && (strings.Contains(method, "list") || strings.Contains(method, "get") || strings.Contains(method, "read")):
		return service.ActionHallRead
	case strings.Contains(method, "spectator") && strings.Contains(method, "search"):
		return service.ActionSearchSpectator
	case strings.Contains(method, "spectator") && strings.Contains(method, "create"):
		return service.ActionSpectatorCreate
	case strings.Contains(method, "spectator") && (strings.Contains(method, "list") || strings.Contains(method, "get") || strings.Contains(method, "read")):
		return service.ActionSpectatorRead
	default:
		return service.Action("")
	}
}

func metadataValue(md metadata.MD, key, fallback string) string {
	value := strings.TrimSpace(first(md.Get(key)))
	if value == "" {
		return fallback
	}
	return value
}

func metadataScopes(md metadata.MD) []string {
	var scopes []string

	for _, raw := range md.Get("x-scopes") {
		for _, part := range strings.Split(raw, ",") {
			scope := strings.TrimSpace(part)
			if scope != "" {
				scopes = append(scopes, scope)
			}
		}
	}

	for _, raw := range md.Get("x-scope") {
		scope := strings.TrimSpace(raw)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}

	if len(scopes) == 0 {
		return []string{"cinema"}
	}

	return scopes
}
