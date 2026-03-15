package http

import (
	"net/http"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestResolveHTTPAction(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   service.Action
	}{
		{name: "list films", method: http.MethodGet, path: "/films", want: service.ActionFilmRead},
		{name: "create film", method: http.MethodPost, path: "/films/", want: service.ActionFilmCreate},
		{name: "update film time", method: http.MethodPatch, path: "/films/film-1/time", want: service.ActionFilmUpdateTime},
		{name: "list halls", method: http.MethodGet, path: "/halls/", want: service.ActionHallRead},
		{name: "create hall", method: http.MethodPost, path: "/halls", want: service.ActionHallCreate},
		{name: "create spectator", method: http.MethodPost, path: "/spectators", want: service.ActionSpectatorCreate},
		{name: "search spectator", method: http.MethodGet, path: "/spectators/search", want: service.ActionSearchSpectator},
		{name: "audit", method: http.MethodGet, path: "/audit/", want: service.ActionAuditRead},
		{name: "perf list", method: http.MethodGet, path: "/perf", want: service.ActionPerfRead},
		{name: "perf summary", method: http.MethodGet, path: "/perf/summary", want: service.ActionPerfRead},
		{name: "unknown", method: http.MethodGet, path: "/health", want: service.Action("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveHTTPAction(tt.method, tt.path); got != tt.want {
				t.Fatalf("resolveHTTPAction(%q, %q) = %q, want %q", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
