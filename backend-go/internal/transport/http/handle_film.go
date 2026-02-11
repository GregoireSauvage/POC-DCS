package http

import (
	"errors"
	nethttp "net/http"
	"strconv"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func (s *Server) handleFilms(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodGet {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}
	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)

	films, pctx, err := s.filmFlow.List(r.Context(), principal, reqCtx)
	if err != nil {
		writeError(w, nethttp.StatusInternalServerError, err.Error())
		return
	}
	setPerfHeaders(w, pctx)
	writeJSON(w, nethttp.StatusOK, films)
}

func (s *Server) handleFilmSubroutes(w nethttp.ResponseWriter, r *nethttp.Request) {
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

	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)
	film, pctx, err := s.filmFlow.UpdateTime(r.Context(), principal, reqCtx, parts[0], timeElapsed)
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
