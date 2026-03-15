package http

import (
	nethttp "net/http"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func resolveHTTPAction(method, path string) service.Action {
	normalizedPath := strings.TrimSpace(path)
	if normalizedPath == "" {
		normalizedPath = "/"
	}
	if normalizedPath != "/" {
		normalizedPath = strings.TrimRight(normalizedPath, "/")
		if normalizedPath == "" {
			normalizedPath = "/"
		}
	}

	switch {
	case method == nethttp.MethodGet && normalizedPath == "/films":
		return service.ActionFilmRead
	case method == nethttp.MethodPost && normalizedPath == "/films":
		return service.ActionFilmCreate
	case method == nethttp.MethodPatch && strings.HasPrefix(normalizedPath, "/films/") && strings.HasSuffix(normalizedPath, "/time"):
		return service.ActionFilmUpdateTime
	case method == nethttp.MethodGet && normalizedPath == "/halls":
		return service.ActionHallRead
	case method == nethttp.MethodPost && normalizedPath == "/halls":
		return service.ActionHallCreate
	case method == nethttp.MethodPost && normalizedPath == "/spectators":
		return service.ActionSpectatorCreate
	case method == nethttp.MethodGet && normalizedPath == "/spectators/search":
		return service.ActionSearchSpectator
	case method == nethttp.MethodGet && normalizedPath == "/audit":
		return service.ActionAuditRead
	case method == nethttp.MethodGet && (normalizedPath == "/perf" || normalizedPath == "/perf/summary"):
		return service.ActionPerfRead
	default:
		return service.Action("")
	}
}
