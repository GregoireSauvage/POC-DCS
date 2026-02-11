package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type mockPerfService struct {
	listLogs      []*domain.PerfLog
	listErr       error
	listCalls     int
	lastPrincipal service.Principal
	lastReqCtx    service.RequestContext
	lastLimit     int
	lastAction    *string

	summaryRows        []*domain.PerfSummary
	summaryErr         error
	summaryCalls       int
	lastSummaryAction  *string
	lastCacheLevel     *int
	lastAllCacheLevels bool
}

func (m *mockPerfService) List(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	limit int,
	action *string,
) ([]*domain.PerfLog, error) {
	m.listCalls++
	m.lastPrincipal = principal
	m.lastReqCtx = reqCtx
	m.lastLimit = limit
	m.lastAction = action
	return m.listLogs, m.listErr
}

func (m *mockPerfService) Summary(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	action *string,
	cacheLevel *int,
	allCacheLevels bool,
) ([]*domain.PerfSummary, error) {
	m.summaryCalls++
	m.lastPrincipal = principal
	m.lastReqCtx = reqCtx
	m.lastSummaryAction = action
	m.lastCacheLevel = cacheLevel
	m.lastAllCacheLevels = allCacheLevels
	return m.summaryRows, m.summaryErr
}

func newTestServerWithPerf(t *testing.T, perfSvc *mockPerfService) *Server {
	t.Helper()
	server := newTestServer(t)
	if perfSvc != nil {
		server.perfService = perfSvc
	}
	return server
}

func TestPerf_AdminRole_Returns200(t *testing.T) {
	now := time.Now().UTC()
	logs := []*domain.PerfLog{
		{
			Timestamp:     now.Add(-1 * time.Minute),
			RequestID:     "req-1",
			TenantID:      "t1",
			SubjectUserID: "u1",
			SubjectRole:   "admin",
			Action:        "film.read",
			ResourceType:  "film",
			DCSEnabled:    true,
			CacheLevel:    1,
			TotalMS:       12.34,
		},
	}

	perfSvc := &mockPerfService{listLogs: logs}
	server := newTestServerWithPerf(t, perfSvc)

	req := httptest.NewRequest(http.MethodGet, "/perf?limit=200", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var out []domain.PerfLog
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	if len(out) != 1 || out[0].Action != "film.read" {
		t.Fatalf("expected one perf log for film.read")
	}
	if perfSvc.listCalls != 1 {
		t.Fatalf("expected list called once, got %d", perfSvc.listCalls)
	}
	if perfSvc.lastPrincipal.TenantID != "t1" {
		t.Fatalf("expected tenant_id t1, got %q", perfSvc.lastPrincipal.TenantID)
	}
}

func TestPerf_NonAdminRole_Returns403(t *testing.T) {
	perfSvc := &mockPerfService{listLogs: []*domain.PerfLog{}}
	server := newTestServerWithPerf(t, perfSvc)

	roles := []string{"developer", "agent", "user"}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			token := generateNonAdminToken(t, server, role)
			req := httptest.NewRequest(http.MethodGet, "/perf", nil)
			req.Header.Set("Authorization", token)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for role=%s, got %d", role, rec.Code)
			}
		})
	}
}

func TestPerf_NoJWT_Returns401(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{})
	req := httptest.NewRequest(http.MethodGet, "/perf", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestPerf_InvalidJWT_Returns401(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{})
	invalidTokens := []string{"Bearer not-a-jwt", "Bearer ", "Bearer eyJhbGciOiJIUzI1NiJ9.invalid"}
	for _, token := range invalidTokens {
		req := httptest.NewRequest(http.MethodGet, "/perf", nil)
		req.Header.Set("Authorization", token)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for token=%q, got %d", token, rec.Code)
		}
	}
}

func TestPerf_LimitQueryParam(t *testing.T) {
	perfSvc := &mockPerfService{listLogs: []*domain.PerfLog{}}
	server := newTestServerWithPerf(t, perfSvc)
	auth := adminAuthHeader(t, server)

	tests := []struct {
		name        string
		query       string
		wantStatus  int
		wantLimit   int
		shouldError bool
	}{
		{"valid 50", "?limit=50", http.StatusOK, 50, false},
		{"valid 1000", "?limit=1000", http.StatusOK, 1000, false},
		{"default 200", "", http.StatusOK, 200, false},
		{"invalid non-numeric", "?limit=abc", http.StatusBadRequest, 0, true},
		{"invalid negative", "?limit=-1", http.StatusBadRequest, 0, true},
		{"invalid zero", "?limit=0", http.StatusBadRequest, 0, true},
		{"too large", "?limit=1001", http.StatusBadRequest, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perfSvc.listCalls = 0
			req := httptest.NewRequest(http.MethodGet, "/perf"+tt.query, nil)
			req.Header.Set("Authorization", auth)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d", tt.wantStatus, rec.Code)
			}
			if !tt.shouldError && perfSvc.lastLimit != tt.wantLimit {
				t.Fatalf("expected limit=%d, got %d", tt.wantLimit, perfSvc.lastLimit)
			}
		})
	}
}

func TestPerf_ActionFilterPassedToService(t *testing.T) {
	perfSvc := &mockPerfService{listLogs: []*domain.PerfLog{}}
	server := newTestServerWithPerf(t, perfSvc)
	auth := adminAuthHeader(t, server)

	req := httptest.NewRequest(http.MethodGet, "/perf?action=film.read", nil)
	req.Header.Set("Authorization", auth)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if perfSvc.lastAction == nil || *perfSvc.lastAction != "film.read" {
		t.Fatalf("expected action filter passed to service")
	}
}

func TestPerf_RequestContextForwarded(t *testing.T) {
	perfSvc := &mockPerfService{listLogs: []*domain.PerfLog{}}
	server := newTestServerWithPerf(t, perfSvc)
	auth := adminAuthHeader(t, server)

	req := httptest.NewRequest(http.MethodGet, "/perf", nil)
	req.Header.Set("Authorization", auth)
	req.Header.Set("X-Request-ID", "req-test-123")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if perfSvc.lastReqCtx.RequestID != "req-test-123" {
		t.Fatalf("expected request_id forwarded")
	}
	if perfSvc.lastReqCtx.Env == "" {
		t.Fatalf("expected env set in request context")
	}
}

func TestPerf_ServiceUnavailable_Returns503(t *testing.T) {
	server := newTestServerWithPerf(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/perf", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestPerf_ServiceError_Returns500(t *testing.T) {
	perfSvc := &mockPerfService{listErr: errors.New("db error")}
	server := newTestServerWithPerf(t, perfSvc)

	req := httptest.NewRequest(http.MethodGet, "/perf", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestPerf_EmptyLogs_ReturnsEmptyArray(t *testing.T) {
	perfSvc := &mockPerfService{listLogs: []*domain.PerfLog{}}
	server := newTestServerWithPerf(t, perfSvc)

	req := httptest.NewRequest(http.MethodGet, "/perf", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "[]\n" && rec.Body.String() != "[]" {
		t.Fatalf("expected empty array, got %q", rec.Body.String())
	}
}

func TestPerf_MethodNotAllowed(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{})
	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/perf", nil)
			req.Header.Set("Authorization", adminAuthHeader(t, server))
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 for %s, got %d", method, rec.Code)
			}
		})
	}
}

func TestPerf_ContentTypeJSON(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{listLogs: []*domain.PerfLog{}})
	req := httptest.NewRequest(http.MethodGet, "/perf", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}
