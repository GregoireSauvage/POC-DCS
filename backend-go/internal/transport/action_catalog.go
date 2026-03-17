package transport

import (
	nethttp "net/http"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type HTTPRoute struct {
	Method  string
	Pattern string
}

type ActionMapping struct {
	Action service.Action
	HTTP   []HTTPRoute
	GRPC   []string
}

var actionCatalog = []ActionMapping{
	{
		Action: service.ActionBootstrap,
		GRPC: []string{
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
		},
	},
	{
		Action: service.ActionAuditRead,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodGet, Pattern: "/audit"}},
		GRPC:   []string{"/cinema.v1.AuditService/ListAuditLogs"},
	},
	{
		Action: service.ActionPerfRead,
		HTTP: []HTTPRoute{
			{Method: nethttp.MethodGet, Pattern: "/perf"},
			{Method: nethttp.MethodGet, Pattern: "/perf/summary"},
		},
		GRPC: []string{
			"/cinema.v1.PerfService/ListPerfLogs",
			"/cinema.v1.PerfService/GetPerfSummary",
		},
	},
	{
		Action: service.ActionFilmRead,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodGet, Pattern: "/films"}},
		GRPC: []string{
			"/cinema.v1.FilmService/ListFilms",
			"/cinema.v1.FilmService/GetFilm",
			"/cinema.v1.FilmService/ReadFilm",
		},
	},
	{
		Action: service.ActionFilmCreate,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodPost, Pattern: "/films"}},
		GRPC:   []string{"/cinema.v1.FilmService/CreateFilm"},
	},
	{
		Action: service.ActionFilmUpdateTime,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodPatch, Pattern: "/films/{film_id}/time"}},
		GRPC:   []string{"/cinema.v1.FilmService/UpdateFilmTime"},
	},
	{
		Action: service.ActionHallRead,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodGet, Pattern: "/halls"}},
		GRPC: []string{
			"/cinema.v1.HallService/ListHalls",
			"/cinema.v1.HallService/GetHall",
			"/cinema.v1.HallService/ReadHall",
		},
	},
	{
		Action: service.ActionHallCreate,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodPost, Pattern: "/halls"}},
		GRPC:   []string{"/cinema.v1.HallService/CreateHall"},
	},
	{
		Action: service.ActionSpectatorRead,
		GRPC: []string{
			"/cinema.v1.SpectatorService/ListSpectators",
			"/cinema.v1.SpectatorService/GetSpectator",
			"/cinema.v1.SpectatorService/ReadSpectator",
		},
	},
	{
		Action: service.ActionSpectatorCreate,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodPost, Pattern: "/spectators"}},
		GRPC:   []string{"/cinema.v1.SpectatorService/CreateSpectator"},
	},
	{
		Action: service.ActionSearchSpectator,
		HTTP:   []HTTPRoute{{Method: nethttp.MethodGet, Pattern: "/spectators/search"}},
		GRPC:   []string{"/cinema.v1.SpectatorService/SearchSpectators"},
	},
}

func ResolveHTTPAction(method, path string) service.Action {
	normalizedMethod := strings.ToUpper(strings.TrimSpace(method))
	normalizedPath := normalizeHTTPPath(path)

	for _, mapping := range actionCatalog {
		for _, route := range mapping.HTTP {
			if strings.ToUpper(strings.TrimSpace(route.Method)) != normalizedMethod {
				continue
			}
			if matchHTTPPattern(normalizedPath, route.Pattern) {
				return mapping.Action
			}
		}
	}

	return service.Action("")
}

func ResolveGRPCAction(fullMethod string) service.Action {
	normalized := strings.ToLower(strings.TrimSpace(fullMethod))
	for _, mapping := range actionCatalog {
		for _, candidate := range mapping.GRPC {
			if strings.ToLower(strings.TrimSpace(candidate)) == normalized {
				return mapping.Action
			}
		}
	}

	return service.Action("")
}

func normalizeHTTPPath(path string) string {
	normalizedPath := strings.TrimSpace(path)
	if normalizedPath == "" {
		return "/"
	}
	if normalizedPath != "/" {
		normalizedPath = strings.TrimRight(normalizedPath, "/")
		if normalizedPath == "" {
			return "/"
		}
	}
	return normalizedPath
}

func matchHTTPPattern(path, pattern string) bool {
	path = normalizeHTTPPath(path)
	pattern = normalizeHTTPPath(pattern)
	if path == pattern {
		return true
	}

	pathSegments := splitSegments(path)
	patternSegments := splitSegments(pattern)
	if len(pathSegments) != len(patternSegments) {
		return false
	}

	for i := range pathSegments {
		segment := patternSegments[i]
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			if pathSegments[i] == "" {
				return false
			}
			continue
		}
		if pathSegments[i] != segment {
			return false
		}
	}

	return true
}

func splitSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
