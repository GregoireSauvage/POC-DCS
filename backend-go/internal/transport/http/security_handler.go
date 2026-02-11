package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	nethttp "net/http"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type adminSettingsUpdate struct {
	DCSMode    *string `json:"dcs_mode"`
	CacheLevel *int    `json:"cache_level"`
}

func (s *Server) handleLogin(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodPost {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}

	// Check if auth service is available
	if s.authService == nil {
		writeError(w, nethttp.StatusServiceUnavailable, "authentication service unavailable")
		return
	}

	var req service.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nethttp.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate required fields
	if strings.TrimSpace(req.Username) == "" {
		writeError(w, nethttp.StatusBadRequest, "username is required")
		return
	}
	if strings.TrimSpace(req.Password) == "" {
		writeError(w, nethttp.StatusBadRequest, "password is required")
		return
	}

	// Attempt login
	resp, err := s.authService.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			writeError(w, nethttp.StatusUnauthorized, "invalid credentials")
		} else {
			s.logger.Error("login failed", slog.String("error", err.Error()), slog.String("username", req.Username))
			writeError(w, nethttp.StatusInternalServerError, "internal server error")
		}
		return
	}

	writeJSON(w, nethttp.StatusOK, resp)
}

func (s *Server) handleAdminSettings(w nethttp.ResponseWriter, r *nethttp.Request) {
	switch r.Method {
	case nethttp.MethodGet:
		writeJSON(w, nethttp.StatusOK, map[string]interface{}{
			"dcs_mode":    s.runtime.Mode(),
			"cache_level": s.runtime.CacheLevel(),
		})
		return
	case nethttp.MethodPatch:
		var payload adminSettingsUpdate
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, nethttp.StatusBadRequest, "invalid JSON body")
			return
		}
		if payload.DCSMode != nil {
			mode := strings.ToLower(strings.TrimSpace(*payload.DCSMode))
			if mode != "on" && mode != "off" {
				writeError(w, nethttp.StatusBadRequest, "dcs_mode must be 'on' or 'off'")
				return
			}
		}
		if payload.CacheLevel != nil && *payload.CacheLevel < 0 {
			writeError(w, nethttp.StatusBadRequest, "cache_level must be >= 0")
			return
		}

		s.runtime.Set(payload.DCSMode, payload.CacheLevel)
		s.cache.ClearAll()
		writeJSON(w, nethttp.StatusOK, map[string]interface{}{
			"dcs_mode":    s.runtime.Mode(),
			"cache_level": s.runtime.CacheLevel(),
		})
		return
	default:
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}
}
