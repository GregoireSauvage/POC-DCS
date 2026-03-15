package http

import (
	"errors"
	nethttp "net/http"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func (s *Server) handleAudit(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodGet {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}

	if s.auditService == nil {
		writeError(w, nethttp.StatusServiceUnavailable, "audit service unavailable")
		return
	}

	limit, err := parseLimit(r)
	if err != nil {
		writeError(w, nethttp.StatusBadRequest, "limit must be between 1 and 1000")
		return
	}

	access, ok := accessContextFromRequest(r)
	if !ok {
		writeError(w, nethttp.StatusInternalServerError, "missing access context")
		return
	}

	logs, err := s.auditService.List(r.Context(), access.Principal, access.Request, limit)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, nethttp.StatusForbidden, "admin role required")
			return
		}
		writeError(w, nethttp.StatusInternalServerError, "failed to retrieve audit logs")
		return
	}
	if logs == nil {
		logs = []*domain.AuditLog{}
	}
	writeJSON(w, nethttp.StatusOK, logs)
}
