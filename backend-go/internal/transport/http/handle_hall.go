package http

import (
	"encoding/json"
	"errors"
	nethttp "net/http"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type hallCreateRequest struct {
	Name          string `json:"name"`
	OwnerUserID   string `json:"owner_user_id"`
	CurrentFilmID string `json:"current_film_id"`
}

// handleHalls dispatches GET and POST /halls
func (s *Server) handleHalls(w nethttp.ResponseWriter, r *nethttp.Request) {
	switch r.Method {
	case nethttp.MethodGet:
		s.handleListHalls(w, r)
	case nethttp.MethodPost:
		s.handleCreateHall(w, r)
	default:
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
	}
}

// handleListHalls handles GET /halls
func (s *Server) handleListHalls(w nethttp.ResponseWriter, r *nethttp.Request) {
	// 1. Extract principal and request context
	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)

	// 2. Call service
	halls, pctx, err := s.hallService.List(r.Context(), principal, reqCtx)
	if err != nil {
		s.logger.Error("failed to list halls", "error", err)
		writeError(w, nethttp.StatusInternalServerError, "internal server error")
		return
	}

	// 3. Set perf headers
	setPerfHeaders(w, pctx)

	// 4. Return response
	writeJSON(w, nethttp.StatusOK, halls)
}

// handleCreateHall handles POST /halls
func (s *Server) handleCreateHall(w nethttp.ResponseWriter, r *nethttp.Request) {
	// 1. Method check
	if r.Method != nethttp.MethodPost {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}

	// 2. Parse request body
	var req hallCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nethttp.StatusBadRequest, "invalid JSON body")
		return
	}

	// 3. Validate required fields
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, nethttp.StatusBadRequest, "name is required")
		return
	}
	if strings.TrimSpace(req.OwnerUserID) == "" {
		writeError(w, nethttp.StatusBadRequest, "owner_user_id is required")
		return
	}
	if strings.TrimSpace(req.CurrentFilmID) == "" {
		writeError(w, nethttp.StatusBadRequest, "current_film_id is required")
		return
	}

	// 4. Extract principal and request context
	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)

	// 5. Call service
	hall, pctx, err := s.hallService.Create(r.Context(), principal, reqCtx, service.HallCreateInput{
		Name:          strings.TrimSpace(req.Name),
		OwnerUserID:   strings.TrimSpace(req.OwnerUserID),
		CurrentFilmID: strings.TrimSpace(req.CurrentFilmID),
	})
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, nethttp.StatusForbidden, "forbidden")
		} else {
			s.logger.Error("failed to create hall", "error", err)
			writeError(w, nethttp.StatusInternalServerError, "internal server error")
		}
		return
	}

	// 6. Set perf headers
	setPerfHeaders(w, pctx)

	// 7. Return response (200 OK for Python parity, not 201)
	writeJSON(w, nethttp.StatusOK, hall)
}
