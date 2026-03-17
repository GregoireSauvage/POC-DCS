package transport

import (
	"net/http"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestActionParityAcrossHTTPAndGRPC(t *testing.T) {
	tests := []struct {
		name       string
		httpMethod string
		httpPath   string
		grpcMethod string
		want       service.Action
	}{
		{name: "bootstrap", grpcMethod: "/grpc.health.v1.Health/Check", want: service.ActionBootstrap},
		{name: "audit read", httpMethod: http.MethodGet, httpPath: "/audit", grpcMethod: "/cinema.v1.AuditService/ListAuditLogs", want: service.ActionAuditRead},
		{name: "perf read", httpMethod: http.MethodGet, httpPath: "/perf/summary", grpcMethod: "/cinema.v1.PerfService/GetPerfSummary", want: service.ActionPerfRead},
		{name: "film read", httpMethod: http.MethodGet, httpPath: "/films", grpcMethod: "/cinema.v1.FilmService/ListFilms", want: service.ActionFilmRead},
		{name: "film create", httpMethod: http.MethodPost, httpPath: "/films", grpcMethod: "/cinema.v1.FilmService/CreateFilm", want: service.ActionFilmCreate},
		{name: "film update", httpMethod: http.MethodPatch, httpPath: "/films/film-1/time", grpcMethod: "/cinema.v1.FilmService/UpdateFilmTime", want: service.ActionFilmUpdateTime},
		{name: "hall read", httpMethod: http.MethodGet, httpPath: "/halls", grpcMethod: "/cinema.v1.HallService/ListHalls", want: service.ActionHallRead},
		{name: "hall create", httpMethod: http.MethodPost, httpPath: "/halls", grpcMethod: "/cinema.v1.HallService/CreateHall", want: service.ActionHallCreate},
		{name: "spectator create", httpMethod: http.MethodPost, httpPath: "/spectators", grpcMethod: "/cinema.v1.SpectatorService/CreateSpectator", want: service.ActionSpectatorCreate},
		{name: "spectator search", httpMethod: http.MethodGet, httpPath: "/spectators/search", grpcMethod: "/cinema.v1.SpectatorService/SearchSpectators", want: service.ActionSearchSpectator},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.httpMethod != "" {
				if got := ResolveHTTPAction(tt.httpMethod, tt.httpPath); got != tt.want {
					t.Fatalf("ResolveHTTPAction(%q, %q) = %q, want %q", tt.httpMethod, tt.httpPath, got, tt.want)
				}
			}
			if tt.grpcMethod != "" {
				if got := ResolveGRPCAction(tt.grpcMethod); got != tt.want {
					t.Fatalf("ResolveGRPCAction(%q) = %q, want %q", tt.grpcMethod, got, tt.want)
				}
			}
		})
	}
}
