package grpc

import (
	"context"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	transportcore "github.com/neoweyss/poc-dcs/backend-go/internal/transport"
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
		Principal: transportcore.NormalizePrincipal(
			metadataValue(md, "x-tenant-id", ""),
			metadataValue(md, "x-user-id", ""),
			metadataValue(md, "x-username", ""),
			metadataValue(md, "x-role", ""),
			metadataScopes(md),
		),
		Request: transportcore.BuildRequestContext(
			metadataValue(md, "x-request-id", ""),
			metadataValue(md, "x-real-ip", ""),
			env,
			transportcore.RequestContextDefaults{
				RequestIDFallback: "grpc-no-request-id",
				Channel:           "grpc",
				Purpose:           "cinema_ops",
				DeviceTrust:       0.8,
			},
		),
		Action: transportcore.ResolveGRPCAction(fullMethod),
	}
}

func resolveGRPCAction(fullMethod string) service.Action {
	return transportcore.ResolveGRPCAction(fullMethod)
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
