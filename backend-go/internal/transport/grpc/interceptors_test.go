package grpc

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestResolveGRPCAction(t *testing.T) {
	tests := []struct {
		name       string
		fullMethod string
		want       service.Action
	}{
		{name: "health", fullMethod: "/grpc.health.v1.Health/Check", want: service.ActionBootstrap},
		{name: "film list", fullMethod: "/cinema.v1.FilmService/ListFilms", want: service.ActionFilmRead},
		{name: "film create", fullMethod: "/cinema.v1.FilmService/CreateFilm", want: service.ActionFilmCreate},
		{name: "film update", fullMethod: "/cinema.v1.FilmService/UpdateFilmTime", want: service.ActionFilmUpdateTime},
		{name: "hall list", fullMethod: "/cinema.v1.HallService/ListHalls", want: service.ActionHallRead},
		{name: "spectator search", fullMethod: "/cinema.v1.SpectatorService/SearchSpectators", want: service.ActionSearchSpectator},
		{name: "perf", fullMethod: "/cinema.v1.PerfService/GetPerfSummary", want: service.ActionPerfRead},
		{name: "unknown", fullMethod: "/cinema.v1.UnknownService/Ping", want: service.Action("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveGRPCAction(tt.fullMethod); got != tt.want {
				t.Fatalf("resolveGRPCAction(%q) = %q, want %q", tt.fullMethod, got, tt.want)
			}
		})
	}
}

func TestUnaryAccessContextInterceptor_BuildsAccessContext(t *testing.T) {
	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-user-id", "u-admin",
		"x-tenant-id", "t1",
		"x-username", "admin",
		"x-role", "admin",
		"x-scopes", "cinema,audit",
	))

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		access, ok := service.AccessContextFromContext(ctx)
		if !ok {
			t.Fatal("expected access context in gRPC context")
		}
		if access.Principal.UserID != "u-admin" {
			t.Fatalf("expected user id u-admin, got %q", access.Principal.UserID)
		}
		if access.Action != service.ActionBootstrap {
			t.Fatalf("expected bootstrap action, got %q", access.Action)
		}
		if access.Request.RequestID != "grpc-no-request-id" {
			t.Fatalf("expected default request id, got %q", access.Request.RequestID)
		}
		if len(access.Principal.Scopes) != 2 {
			t.Fatalf("expected 2 scopes, got %d", len(access.Principal.Scopes))
		}
		return "ok", nil
	}

	requestID := unaryRequestIDInterceptor()
	access := unaryAccessContextInterceptor("test", slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	_, err := requestID(ctx, nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return access(ctx, req, info, handler)
	})
	if err != nil {
		t.Fatalf("unexpected interceptor error: %v", err)
	}
}

func TestBuildAccessContext_DefaultsWithoutMetadata(t *testing.T) {
	access := buildAccessContext(context.Background(), "/grpc.health.v1.Health/Check", "test")

	if access.Principal.TenantID != "t1" {
		t.Fatalf("expected default tenant id t1, got %q", access.Principal.TenantID)
	}
	if access.Principal.UserID != "u-dev" {
		t.Fatalf("expected default user id u-dev, got %q", access.Principal.UserID)
	}
	if access.Principal.Role != "developer" {
		t.Fatalf("expected default role developer, got %q", access.Principal.Role)
	}
	if access.Request.RequestID != "grpc-no-request-id" {
		t.Fatalf("expected default request id grpc-no-request-id, got %q", access.Request.RequestID)
	}
	if access.Request.Channel != "grpc" {
		t.Fatalf("expected channel grpc, got %q", access.Request.Channel)
	}
	if access.Action != service.ActionBootstrap {
		t.Fatalf("expected bootstrap action, got %q", access.Action)
	}
}
