package http

import (
	"encoding/json"
	"errors"
	nethttp "net/http"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// SpectatorCreateRequest is the HTTP request body for POST /spectators
type SpectatorCreateRequest struct {
	HallID     string `json:"hall_id"`
	Name       string `json:"name"`
	Age        int    `json:"age"`
	ExternalID string `json:"external_id"`
}

// handleSpectators handles POST /spectators
func (s *Server) handleSpectators(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodPost {
		nethttp.Error(w, "Method not allowed", nethttp.StatusMethodNotAllowed)
		return
	}

	var req SpectatorCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		nethttp.Error(w, "invalid request body", nethttp.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.HallID == "" {
		nethttp.Error(w, "hall_id is required", nethttp.StatusUnprocessableEntity)
		return
	}
	if req.Name == "" {
		nethttp.Error(w, "name is required", nethttp.StatusUnprocessableEntity)
		return
	}
	if req.ExternalID == "" {
		nethttp.Error(w, "external_id is required", nethttp.StatusUnprocessableEntity)
		return
	}

	access, ok := accessContextFromRequest(r)
	if !ok {
		writeError(w, nethttp.StatusInternalServerError, "missing access context")
		return
	}

	spectator, _, err := s.spectatorService.Create(r.Context(), access.Principal, access.Request, service.SpectatorCreateInput{
		HallID:     req.HallID,
		Name:       req.Name,
		Age:        req.Age,
		ExternalID: req.ExternalID,
	})
	if errors.Is(err, service.ErrForbidden) {
		nethttp.Error(w, "Forbidden", nethttp.StatusForbidden)
		return
	}
	if errors.Is(err, service.ErrNotFound) {
		nethttp.Error(w, "Hall not found", nethttp.StatusNotFound)
		return
	}
	if err != nil {
		s.logger.Error(
			"spectator create error",
			"error", err.Error(),
			"request_id", access.Request.RequestID,
			"tenant_id", access.Principal.TenantID,
		)
		nethttp.Error(w, "internal error", nethttp.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(nethttp.StatusOK)
	json.NewEncoder(w).Encode(spectator)
}

// handleSearchSpectators handles GET /spectators/search?external_id=...
func (s *Server) handleSearchSpectators(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodGet {
		nethttp.Error(w, "Method not allowed", nethttp.StatusMethodNotAllowed)
		return
	}

	externalID := r.URL.Query().Get("external_id")
	if externalID == "" {
		nethttp.Error(w, "external_id query parameter is required", nethttp.StatusUnprocessableEntity)
		return
	}

	access, ok := accessContextFromRequest(r)
	if !ok {
		writeError(w, nethttp.StatusInternalServerError, "missing access context")
		return
	}

	spectators, _, err := s.spectatorService.Search(r.Context(), access.Principal, access.Request, externalID)
	if errors.Is(err, service.ErrForbidden) {
		nethttp.Error(w, "Forbidden", nethttp.StatusForbidden)
		return
	}
	if err != nil {
		s.logger.Error("spectator search error", "error", err.Error())
		nethttp.Error(w, "internal error", nethttp.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(spectators)
}
