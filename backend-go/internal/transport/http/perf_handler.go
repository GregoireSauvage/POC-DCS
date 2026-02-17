package http

import (
	"errors"
	nethttp "net/http"
	"strconv"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func (s *Server) handlePerf(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodGet {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}

	if s.perfService == nil {
		writeError(w, nethttp.StatusServiceUnavailable, "perf service unavailable")
		return
	}

	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, nethttp.StatusBadRequest, "limit must be between 1 and 1000")
		return
	}

	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)

	action := parseActionParam(r)
	source := parseSourceParam(r)
	if source == nil && strings.TrimSpace(s.cfg.PerfSource) != "" {
		defaultSource := strings.TrimSpace(s.cfg.PerfSource)
		source = &defaultSource
	}
	s.logger.Debug("perf list request",
		"request_id", reqCtx.RequestID,
		"tenant_id", principal.TenantID,
		"user_id", principal.UserID,
		"role", principal.Role,
		"dcs_enabled", s.runtime.DcsEnabled(),
		"action", derefString(action),
		"source", derefString(source),
		"limit", limit,
	)
	logs, err := s.perfService.List(r.Context(), principal, reqCtx, limit, action, source)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.logger.Warn("perf list forbidden",
				"request_id", reqCtx.RequestID,
				"tenant_id", principal.TenantID,
				"user_id", principal.UserID,
				"role", principal.Role,
				"action", derefString(action),
				"source", derefString(source),
			)
			writeError(w, nethttp.StatusForbidden, "admin role required")
			return
		}
		s.logger.Error("perf list failed",
			"request_id", reqCtx.RequestID,
			"tenant_id", principal.TenantID,
			"user_id", principal.UserID,
			"role", principal.Role,
			"error", err.Error(),
		)
		writeError(w, nethttp.StatusInternalServerError, "failed to retrieve perf logs")
		return
	}
	if logs == nil {
		logs = []*domain.PerfLog{}
	}
	s.logger.Debug("perf list response",
		"request_id", reqCtx.RequestID,
		"tenant_id", principal.TenantID,
		"count", len(logs),
	)
	writeJSON(w, nethttp.StatusOK, logs)
}

func (s *Server) handlePerfSummary(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodGet {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}

	if s.perfService == nil {
		writeError(w, nethttp.StatusServiceUnavailable, "perf service unavailable")
		return
	}

	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)

	action := parseActionParam(r)
	source := parseSourceParam(r)
	if source == nil && strings.TrimSpace(s.cfg.PerfSource) != "" {
		defaultSource := strings.TrimSpace(s.cfg.PerfSource)
		source = &defaultSource
	}
	allCacheLevels, err := parseBoolParam(r, "all_cache_levels")
	if err != nil {
		writeError(w, nethttp.StatusBadRequest, "all_cache_levels must be a boolean")
		return
	}

	var cacheLevel *int
	if !allCacheLevels {
		rawCache := strings.TrimSpace(r.URL.Query().Get("cache_level"))
		if rawCache == "" {
			defaultLevel := s.runtime.CacheLevel()
			cacheLevel = &defaultLevel
		} else {
			level, err := strconv.Atoi(rawCache)
			if err != nil || level < 0 {
				writeError(w, nethttp.StatusBadRequest, "cache_level must be >= 0")
				return
			}
			cacheLevel = &level
		}
	}

	s.logger.Debug("perf summary request",
		"request_id", reqCtx.RequestID,
		"tenant_id", principal.TenantID,
		"user_id", principal.UserID,
		"role", principal.Role,
		"dcs_enabled", s.runtime.DcsEnabled(),
		"action", derefString(action),
		"source", derefString(source),
		"cache_level", derefInt(cacheLevel),
		"all_cache_levels", allCacheLevels,
	)
	rows, err := s.perfService.Summary(r.Context(), principal, reqCtx, action, cacheLevel, allCacheLevels, source)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			s.logger.Warn("perf summary forbidden",
				"request_id", reqCtx.RequestID,
				"tenant_id", principal.TenantID,
				"user_id", principal.UserID,
				"role", principal.Role,
				"action", derefString(action),
				"source", derefString(source),
			)
			writeError(w, nethttp.StatusForbidden, "admin role required")
			return
		}
		s.logger.Error("perf summary failed",
			"request_id", reqCtx.RequestID,
			"tenant_id", principal.TenantID,
			"user_id", principal.UserID,
			"role", principal.Role,
			"error", err.Error(),
		)
		writeError(w, nethttp.StatusInternalServerError, "failed to retrieve perf summary")
		return
	}
	if rows == nil {
		rows = []*domain.PerfSummary{}
	}
	s.logger.Debug("perf summary response",
		"request_id", reqCtx.RequestID,
		"tenant_id", principal.TenantID,
		"count", len(rows),
	)
	writeJSON(w, nethttp.StatusOK, rows)
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
