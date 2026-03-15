package http

import (
	"encoding/json"
	"errors"
	nethttp "net/http"
	"strconv"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func (s *Server) handleFilms(w nethttp.ResponseWriter, r *nethttp.Request) {
	switch r.Method {
	case nethttp.MethodGet:
		s.handleListFilms(w, r)
	case nethttp.MethodPost:
		s.handleCreateFilm(w, r)
	default:
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
	}
}

func (s *Server) handleListFilms(w nethttp.ResponseWriter, r *nethttp.Request) {
	access, ok := accessContextFromRequest(r)
	if !ok {
		writeError(w, nethttp.StatusInternalServerError, "missing access context")
		return
	}

	films, pctx, err := s.filmFlow.List(r.Context(), access.Principal, access.Request)
	if err != nil {
		writeError(w, nethttp.StatusInternalServerError, err.Error())
		return
	}
	setPerfHeaders(w, pctx)
	writeJSON(w, nethttp.StatusOK, films)
}

func (s *Server) handleFilmSubroutes(w nethttp.ResponseWriter, r *nethttp.Request) {
	// Allow /films/ to behave like /films for GET/POST (frontend uses trailing slash)
	if r.URL.Path == "/films/" || r.URL.Path == "/films" {
		s.handleFilms(w, r)
		return
	}
	if r.Method != nethttp.MethodPatch {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/films/"), "/")
	if len(parts) != 2 || parts[1] != "time" || strings.TrimSpace(parts[0]) == "" {
		writeError(w, nethttp.StatusNotFound, "not found")
		return
	}
	timeElapsedRaw := r.URL.Query().Get("time_elapsed")
	timeElapsed, err := strconv.Atoi(timeElapsedRaw)
	if err != nil || timeElapsed < 0 {
		writeError(w, nethttp.StatusBadRequest, "time_elapsed must be a non-negative integer")
		return
	}

	access, ok := accessContextFromRequest(r)
	if !ok {
		writeError(w, nethttp.StatusInternalServerError, "missing access context")
		return
	}

	film, pctx, err := s.filmFlow.UpdateTime(r.Context(), access.Principal, access.Request, parts[0], timeElapsed)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			writeError(w, nethttp.StatusForbidden, "forbidden")
		case errors.Is(err, service.ErrNotFound):
			writeError(w, nethttp.StatusNotFound, "film not found")
		default:
			writeError(w, nethttp.StatusInternalServerError, err.Error())
		}
		return
	}
	setPerfHeaders(w, pctx)
	writeJSON(w, nethttp.StatusOK, film)
}

type filmCreateRequest struct {
	Title       string `json:"title"`
	TimeElapsed int    `json:"time_elapsed"`
}

func (s *Server) handleCreateFilm(w nethttp.ResponseWriter, r *nethttp.Request) {
	// 1. Method check
	if r.Method != nethttp.MethodPost {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}

	// 2. Parse request body
	var req filmCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nethttp.StatusBadRequest, "invalid JSON body")
		return
	}

	// 3. Validate required fields
	if strings.TrimSpace(req.Title) == "" {
		writeError(w, nethttp.StatusBadRequest, "title is required")
		return
	}
	if req.TimeElapsed < 0 {
		writeError(w, nethttp.StatusBadRequest, "time_elapsed must be non-negative")
		return
	}

	access, ok := accessContextFromRequest(r)
	if !ok {
		writeError(w, nethttp.StatusInternalServerError, "missing access context")
		return
	}

	// 5. Call service
	film, pctx, err := s.filmFlow.Create(r.Context(), access.Principal, access.Request, service.FilmCreateInput{
		Title:       strings.TrimSpace(req.Title),
		TimeElapsed: req.TimeElapsed,
	})
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, nethttp.StatusForbidden, "forbidden")
		} else {
			writeError(w, nethttp.StatusInternalServerError, "internal server error")
		}
		return
	}

	// 6. Return response with perf headers
	setPerfHeaders(w, pctx)
	writeJSON(w, nethttp.StatusOK, film)
}
