package grpc

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func unaryRequestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			md = metadata.New(nil)
		}

		if reqID := strings.TrimSpace(first(md.Get("x-request-id"))); reqID == "" {
			md.Set("x-request-id", "grpc-no-request-id")
		}

		ctx = metadata.NewIncomingContext(ctx, md)
		return handler(ctx, req)
	}
}

func unaryAccessContextInterceptor(env string, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		access := buildAccessContext(ctx, info.FullMethod, env)
		if logger != nil {
			logger.Debug("grpc access context built",
				slog.String("request_id", access.Request.RequestID),
				slog.String("tenant_id", access.Principal.TenantID),
				slog.String("user_id", access.Principal.UserID),
				slog.String("role", access.Principal.Role),
				slog.String("action", string(access.Action)),
				slog.String("channel", access.Request.Channel),
				slog.String("full_method", info.FullMethod),
			)
		}
		ctx = withAccessContext(ctx, access)
		return handler(ctx, req)
	}
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
