package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

func TestPerfSummary_AdminRole_Returns200(t *testing.T) {
	avg := 12.34
	rows := []*domain.PerfSummary{
		{Action: "film.read", DCSEnabled: true, CacheLevel: 1, AvgTotalMS: &avg, Count: 10},
	}
	perfSvc := &mockPerfService{summaryRows: rows}
	server := newTestServerWithPerf(t, perfSvc)

	req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out []domain.PerfSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid response: %v", err)
	}
	if len(out) != 1 || out[0].Action != "film.read" {
		t.Fatalf("expected one summary row for film.read")
	}
	if perfSvc.lastSummarySource == nil || *perfSvc.lastSummarySource != server.cfg.PerfSource {
		t.Fatalf("expected default source %q, got %v", server.cfg.PerfSource, perfSvc.lastSummarySource)
	}
}

func TestPerfSummary_SourceQueryParam(t *testing.T) {
	perfSvc := &mockPerfService{summaryRows: []*domain.PerfSummary{}}
	server := newTestServerWithPerf(t, perfSvc)

	req := httptest.NewRequest(http.MethodGet, "/perf/summary?source=go", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if perfSvc.lastSummarySource == nil || *perfSvc.lastSummarySource != "go" {
		t.Fatalf("expected source go, got %v", perfSvc.lastSummarySource)
	}
}

func TestPerfSummary_NonAdminRole_Returns403(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{})
	roles := []string{"developer", "agent", "user"}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			token := generateNonAdminToken(t, server, role)
			req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
			req.Header.Set("Authorization", token)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
		})
	}
}

func TestPerfSummary_NoJWT_Returns401(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{})
	req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestPerfSummary_InvalidJWT_Returns401(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{})
	invalidTokens := []string{"Bearer not-a-jwt", "Bearer ", "Bearer eyJhbGciOiJIUzI1NiJ9.invalid"}
	for _, token := range invalidTokens {
		req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
		req.Header.Set("Authorization", token)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for token=%q, got %d", token, rec.Code)
		}
	}
}

func TestPerfSummary_CacheLevelParam(t *testing.T) {
	perfSvc := &mockPerfService{summaryRows: []*domain.PerfSummary{}}
	server := newTestServerWithPerf(t, perfSvc)
	auth := adminAuthHeader(t, server)

	tests := []struct {
		name       string
		query      string
		wantStatus int
		wantLevel  *int
	}{
		{"valid cache_level", "?cache_level=2", http.StatusOK, intPtr(2)},
		{"default cache_level", "", http.StatusOK, intPtr(server.runtime.CacheLevel())},
		{"invalid cache_level", "?cache_level=-1", http.StatusBadRequest, nil},
		{"non numeric", "?cache_level=abc", http.StatusBadRequest, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/perf/summary"+tt.query, nil)
			req.Header.Set("Authorization", auth)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d", tt.wantStatus, rec.Code)
			}
			if tt.wantStatus == http.StatusOK {
				if tt.wantLevel == nil || perfSvc.lastCacheLevel == nil || *perfSvc.lastCacheLevel != *tt.wantLevel {
					t.Fatalf("expected cache_level=%v, got %v", tt.wantLevel, perfSvc.lastCacheLevel)
				}
			}
		})
	}
}

func TestPerfSummary_AllCacheLevelsParam(t *testing.T) {
	perfSvc := &mockPerfService{summaryRows: []*domain.PerfSummary{}}
	server := newTestServerWithPerf(t, perfSvc)
	auth := adminAuthHeader(t, server)

	req := httptest.NewRequest(http.MethodGet, "/perf/summary?all_cache_levels=1", nil)
	req.Header.Set("Authorization", auth)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !perfSvc.lastAllCacheLevels {
		t.Fatalf("expected all_cache_levels=true")
	}
	if perfSvc.lastCacheLevel != nil {
		t.Fatalf("expected cache_level nil when all_cache_levels=true")
	}
}

func TestPerfSummary_ActionFilterPassedToService(t *testing.T) {
	perfSvc := &mockPerfService{summaryRows: []*domain.PerfSummary{}}
	server := newTestServerWithPerf(t, perfSvc)
	auth := adminAuthHeader(t, server)

	req := httptest.NewRequest(http.MethodGet, "/perf/summary?action=film.read", nil)
	req.Header.Set("Authorization", auth)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if perfSvc.lastSummaryAction == nil || *perfSvc.lastSummaryAction != "film.read" {
		t.Fatalf("expected action filter passed to service")
	}
}

func TestPerfSummary_ServiceUnavailable_Returns503(t *testing.T) {
	server := newTestServerWithPerf(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestPerfSummary_ServiceError_Returns500(t *testing.T) {
	perfSvc := &mockPerfService{summaryErr: errors.New("db error")}
	server := newTestServerWithPerf(t, perfSvc)
	req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestPerfSummary_EmptyArray(t *testing.T) {
	perfSvc := &mockPerfService{summaryRows: []*domain.PerfSummary{}}
	server := newTestServerWithPerf(t, perfSvc)
	req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
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

func TestPerfSummary_MethodNotAllowed(t *testing.T) {
	server := newTestServerWithPerf(t, &mockPerfService{})
	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/perf/summary", nil)
			req.Header.Set("Authorization", adminAuthHeader(t, server))
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 for %s, got %d", method, rec.Code)
			}
		})
	}
}

func TestPerfSummary_ContentTypeJSON(t *testing.T) {
	perfSvc := &mockPerfService{summaryRows: []*domain.PerfSummary{}}
	server := newTestServerWithPerf(t, perfSvc)
	req := httptest.NewRequest(http.MethodGet, "/perf/summary", nil)
	req.Header.Set("Authorization", adminAuthHeader(t, server))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
}

func intPtr(v int) *int {
	return &v
}
