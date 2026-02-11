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
	logs, err := s.perfService.List(r.Context(), principal, reqCtx, limit, action)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, nethttp.StatusForbidden, "admin role required")
			return
		}
		writeError(w, nethttp.StatusInternalServerError, "failed to retrieve perf logs")
		return
	}
	if logs == nil {
		logs = []*domain.PerfLog{}
	}
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

	rows, err := s.perfService.Summary(r.Context(), principal, reqCtx, action, cacheLevel, allCacheLevels)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, nethttp.StatusForbidden, "admin role required")
			return
		}
		writeError(w, nethttp.StatusInternalServerError, "failed to retrieve perf summary")
		return
	}
	if rows == nil {
		rows = []*domain.PerfSummary{}
	}
	writeJSON(w, nethttp.StatusOK, rows)
}
