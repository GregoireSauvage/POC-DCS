package http

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// mockAuditLogRepository implements repository.AuditLogRepository interface for testing
type mockAuditLogRepository struct {
	logs         []*domain.AuditLog
	err          error
	listCalls    int
	lastTenantID string
	lastLimit    int
}

func (m *mockAuditLogRepository) List(ctx context.Context, tenantID string, limit int) ([]*domain.AuditLog, error) {
	m.listCalls++
	m.lastTenantID = tenantID
	m.lastLimit = limit
	return m.logs, m.err
}

func (m *mockAuditLogRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	return nil
}

// mockPolicyEnforcer implements service.PolicyEnforcer interface for testing
type mockPolicyEnforcer struct {
	auditDecision      service.AuthorizationDecision
	auditErr           error
	auditReadCalls     int
	lastPrincipal      service.Principal
	lastRequestContext service.RequestContext
}

func (m *mockPolicyEnforcer) EvaluateAuditRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
) (service.AuthorizationDecision, error) {
	m.auditReadCalls++
	m.lastPrincipal = principal
	m.lastRequestContext = reqCtx
	return m.auditDecision, m.auditErr
}

// Implement other PolicyEnforcer methods (not used in audit tests)
func (m *mockPolicyEnforcer) EvaluateFilmUpdateTime(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	filmID string,
) (service.AuthorizationDecision, error) {
	return service.AuthorizationDecision{Allow: true}, nil
}

func (m *mockPolicyEnforcer) EnforceFilmRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	film service.FilmReadInput,
) (service.FilmReadResult, error) {
	return service.FilmReadResult{}, nil
}

func newTestServerWithAudit(t *testing.T, auditRepo *mockAuditLogRepository, enforcer *mockPolicyEnforcer) (*Server, string, *mockAuditLogRepository) {
	t.Helper()
	cfg := &config.Config{
		Env:             "dev",
		Service:         "backend-go-test",
		HTTPAddr:        ":0",
		GRPCAddr:        ":0",
		LogLevel:        slog.LevelError,
		DCSMode:         "on",
		CacheLevel:      1,
		CacheMaxEntries: 100,
		JWTSecret:       "test-secret",
		JWTIssuer:       "test-issuer",
		JWTAudience:     "test-audience",
		JWTTTLMin:       60,
	}

	server := NewServer(cfg, slog.Default(), nil)

	// Create audit service with mock repository and enforcer
	if auditRepo != nil {
		// If no enforcer provided, create a default one that allows
		if enforcer == nil {
			enforcer = &mockPolicyEnforcer{
				auditDecision: service.AuthorizationDecision{Allow: true, Reason: "test_allow"},
			}
		}
		server.auditService = service.NewAuditService(auditRepo, enforcer, slog.Default())
	}

	// Generate admin token
	adminToken := adminAuthHeader(t, server)

	return server, adminToken, auditRepo
}

func generateNonAdminToken(t *testing.T, s *Server, role string) string {
	t.Helper()
	token, err := s.jwtService.GenerateToken(
		types.Principal{
			UserID:   "test-user-id",
			TenantID: "test-tenant",
			Username: "testuser",
			Role:     role,
		}, "")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return "Bearer " + token
}

// Test 1: Admin role returns 200 with audit logs
func TestAudit_AdminRole_Returns200(t *testing.T) {
	now := time.Now().UTC()
	mockLogs := []*domain.AuditLog{
		{
			ID:              1,
			Timestamp:       now.Add(-1 * time.Hour),
			RequestID:       "req-123",
			TenantID:        "t1",
			SubjectUserID:   "u-admin",
			SubjectRole:     "admin",
			Action:          "film.read",
			ResourceType:    "film",
			ResourceID:      "film-1",
			Outcome:         "allow",
			DecisionHash:    "hash-abc",
			FieldsDecrypted: []string{"time_elapsed"},
			FieldsMasked:    []string{},
			FieldsDenied:    []string{},
		},
		{
			ID:              2,
			Timestamp:       now.Add(-2 * time.Hour),
			RequestID:       "req-456",
			TenantID:        "t1",
			SubjectUserID:   "u-dev",
			SubjectRole:     "developer",
			Action:          "film.read",
			ResourceType:    "film",
			ResourceID:      "film-2",
			Outcome:         "allow",
			DecisionHash:    "hash-def",
			FieldsDecrypted: []string{},
			FieldsMasked:    []string{"time_elapsed"},
			FieldsDenied:    []string{},
		},
	}

	auditRepo := &mockAuditLogRepository{logs: mockLogs}
	server, adminToken, _ := newTestServerWithAudit(t, auditRepo, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.Header.Set("Authorization", adminToken)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var logs []domain.AuditLog
	if err := json.Unmarshal(rec.Body.Bytes(), &logs); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(logs) != 2 {
		t.Errorf("expected 2 logs, got %d", len(logs))
	}

	// Verify first log
	if logs[0].ID != 1 {
		t.Errorf("expected log ID 1, got %d", logs[0].ID)
	}
	if logs[0].Action != "film.read" {
		t.Errorf("expected action 'film.read', got %q", logs[0].Action)
	}
	if len(logs[0].FieldsDecrypted) != 1 || logs[0].FieldsDecrypted[0] != "time_elapsed" {
		t.Errorf("expected fields_decrypted=['time_elapsed'], got %v", logs[0].FieldsDecrypted)
	}

	// Verify service was called with correct tenant
	if auditRepo.listCalls != 1 {
		t.Errorf("expected 1 service call, got %d", auditRepo.listCalls)
	}
	if auditRepo.lastTenantID != "t1" {
		t.Errorf("expected tenant_id 't1', got %q", auditRepo.lastTenantID)
	}
}

// Test 2: Non-admin role returns 403
func TestAudit_NonAdminRole_Returns403(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}
	server, _, _ := newTestServerWithAudit(t, auditRepo, nil)

	roles := []string{"developer", "agent", "user"}
	for _, role := range roles {
		t.Run("role="+role, func(t *testing.T) {
			token := generateNonAdminToken(t, server, role)

			req := httptest.NewRequest(http.MethodGet, "/audit", nil)
			req.Header.Set("Authorization", token)
			rec := httptest.NewRecorder()

			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden for role=%s, got %d", role, rec.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to parse error response: %v", err)
			}

			if detail, ok := response["detail"].(string); !ok || detail != "admin role required" {
				t.Errorf("expected 'admin role required', got %v", response["detail"])
			}
		})
	}
}

// Test 2b: DCS denies access (even with admin JWT) returns 403
func TestAudit_DCS_Deny_Returns403(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}

	// Enforcer that denies access
	enforcer := &mockPolicyEnforcer{
		auditDecision: service.AuthorizationDecision{
			Allow:  false,
			Reason: "dcs_policy_deny",
		},
	}

	server, adminToken, _ := newTestServerWithAudit(t, auditRepo, enforcer)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.Header.Set("Authorization", adminToken)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when DCS denies, got %d", rec.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	// Verify DCS was called
	if enforcer.auditReadCalls != 1 {
		t.Errorf("expected DCS EvaluateAuditRead to be called once, got %d", enforcer.auditReadCalls)
	}

	// Verify principal was passed correctly
	if enforcer.lastPrincipal.TenantID != "t1" {
		t.Errorf("expected principal.TenantID='t1', got %q", enforcer.lastPrincipal.TenantID)
	}
}

// Test 3: No JWT returns 401
func TestAudit_NoJWT_Returns401(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}
	server, _, _ := newTestServerWithAudit(t, auditRepo, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	// No Authorization header
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if _, ok := response["detail"]; !ok {
		t.Error("expected 'detail' field in error response")
	}
}

// Test 4: Invalid JWT returns 401
func TestAudit_InvalidJWT_Returns401(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}
	server, _, _ := newTestServerWithAudit(t, auditRepo, nil)

	invalidTokens := []struct {
		name  string
		token string
	}{
		{"malformed", "Bearer not-a-jwt"},
		{"wrong signature", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalid"},
		{"empty", "Bearer "},
	}

	for _, tt := range invalidTokens {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/audit", nil)
			req.Header.Set("Authorization", tt.token)
			rec := httptest.NewRecorder()

			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 for %s, got %d", tt.name, rec.Code)
			}
		})
	}
}

// Test 5: Limit query parameter
func TestAudit_LimitQueryParam(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}
	server, adminToken, _ := newTestServerWithAudit(t, auditRepo, nil)

	tests := []struct {
		name           string
		query          string
		expectedCode   int
		expectedLimit  int
		expectError    bool
	}{
		{
			name:          "valid limit 50",
			query:         "?limit=50",
			expectedCode:  http.StatusOK,
			expectedLimit: 50,
			expectError:   false,
		},
		{
			name:          "valid limit 1000",
			query:         "?limit=1000",
			expectedCode:  http.StatusOK,
			expectedLimit: 1000,
			expectError:   false,
		},
		{
			name:          "no limit (default 200)",
			query:         "",
			expectedCode:  http.StatusOK,
			expectedLimit: 200,
			expectError:   false,
		},
		{
			name:         "invalid limit (non-numeric)",
			query:        "?limit=abc",
			expectedCode: http.StatusBadRequest,
			expectError:  true,
		},
		{
			name:         "limit too large",
			query:        "?limit=2000",
			expectedCode: http.StatusBadRequest,
			expectError:  true,
		},
		{
			name:         "limit zero",
			query:        "?limit=0",
			expectedCode: http.StatusBadRequest,
			expectError:  true,
		},
		{
			name:         "limit negative",
			query:        "?limit=-10",
			expectedCode: http.StatusBadRequest,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditRepo.listCalls = 0 // Reset counter

			req := httptest.NewRequest(http.MethodGet, "/audit"+tt.query, nil)
			req.Header.Set("Authorization", adminToken)
			rec := httptest.NewRecorder()

			server.Handler().ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d", tt.expectedCode, rec.Code)
			}

			if !tt.expectError {
				// Verify service was called with correct limit
				if auditRepo.lastLimit != tt.expectedLimit {
					t.Errorf("expected limit %d passed to service, got %d", tt.expectedLimit, auditRepo.lastLimit)
				}
			} else {
				// Verify error response
				var response map[string]interface{}
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to parse error response: %v", err)
				}
				if _, ok := response["detail"]; !ok {
					t.Error("expected 'detail' field in error response")
				}
			}
		})
	}
}

// Test 6: Empty logs returns empty array
func TestAudit_EmptyLogs_ReturnsEmptyArray(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}
	server, adminToken, _ := newTestServerWithAudit(t, auditRepo, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.Header.Set("Authorization", adminToken)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var logs []domain.AuditLog
	if err := json.Unmarshal(rec.Body.Bytes(), &logs); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if logs == nil {
		t.Error("expected empty array [], got null")
	}

	if len(logs) != 0 {
		t.Errorf("expected empty array, got %d logs", len(logs))
	}

	// Verify response is "[]" not "null"
	body := rec.Body.String()
	if body != "[]\n" && body != "[]" {
		t.Errorf("expected JSON array '[]', got %q", body)
	}
}

// Test 7: Service unavailable returns 503
func TestAudit_ServiceUnavailable_Returns503(t *testing.T) {
	// Create server with nil audit service
	server, adminToken, _ := newTestServerWithAudit(t, nil, nil)
	server.auditService = nil // Explicitly set to nil

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.Header.Set("Authorization", adminToken)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable, got %d", rec.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	detail, ok := response["detail"].(string)
	if !ok || detail != "audit service unavailable" {
		t.Errorf("expected 'audit service unavailable', got %v", response["detail"])
	}
}

// Test 8: Database error returns 500
func TestAudit_DatabaseError_Returns500(t *testing.T) {
	auditRepo := &mockAuditLogRepository{
		err: fmt.Errorf("database connection failed"),
	}
	server, adminToken, _ := newTestServerWithAudit(t, auditRepo, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.Header.Set("Authorization", adminToken)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error, got %d", rec.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	detail, ok := response["detail"].(string)
	if !ok || detail != "failed to retrieve audit logs" {
		t.Errorf("expected 'failed to retrieve audit logs', got %v", response["detail"])
	}
}

// Test 9: Tenant isolation
func TestAudit_TenantIsolation(t *testing.T) {
	// Create logs for multiple tenants
	logsForTenant1 := []*domain.AuditLog{
		{ID: 1, TenantID: "tenant-1", Action: "film.read"},
		{ID: 2, TenantID: "tenant-1", Action: "film.update"},
	}

	auditRepo := &mockAuditLogRepository{logs: logsForTenant1}
	server, _, _ := newTestServerWithAudit(t, auditRepo, nil)

	// Generate token for tenant-1
	tenant1Token, err := server.jwtService.GenerateToken(
		types.Principal{
			UserID:   "admin-1",
			TenantID: "tenant-1",
			Username: "admin1",
			Role:     "admin",
		}, "")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.Header.Set("Authorization", "Bearer "+tenant1Token)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// Verify service was called with correct tenant ID
	if auditRepo.lastTenantID != "tenant-1" {
		t.Errorf("expected service called with tenant_id='tenant-1', got %q", auditRepo.lastTenantID)
	}

	var logs []domain.AuditLog
	if err := json.Unmarshal(rec.Body.Bytes(), &logs); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// All returned logs should belong to tenant-1
	for _, log := range logs {
		if log.TenantID != "tenant-1" {
			t.Errorf("expected all logs to have tenant_id='tenant-1', found %q", log.TenantID)
		}
	}
}

// Test 10: Method not allowed
func TestAudit_MethodNotAllowed(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}
	server, adminToken, _ := newTestServerWithAudit(t, auditRepo, nil)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/audit", nil)
			req.Header.Set("Authorization", adminToken)
			rec := httptest.NewRecorder()

			server.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 Method Not Allowed for %s, got %d", method, rec.Code)
			}
		})
	}
}

// Test 11: Content-Type header is application/json
func TestAudit_ContentTypeJSON(t *testing.T) {
	auditRepo := &mockAuditLogRepository{logs: []*domain.AuditLog{}}
	server, adminToken, _ := newTestServerWithAudit(t, auditRepo, nil)

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.Header.Set("Authorization", adminToken)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}
}

// Test 12: DCS is called with correct parameters on success
func TestAudit_DCS_CalledWithCorrectParams(t *testing.T) {
	mockLogs := []*domain.AuditLog{
		{ID: 1, TenantID: "tenant-test", Action: "film.read"},
	}

	auditRepo := &mockAuditLogRepository{logs: mockLogs}

	// Enforcer that allows and tracks calls
	enforcer := &mockPolicyEnforcer{
		auditDecision: service.AuthorizationDecision{
			Allow:  true,
			Reason: "audit_allowed",
		},
	}

	server, _, _ := newTestServerWithAudit(t, auditRepo, enforcer)

	// Generate token for specific tenant
	token, err := server.jwtService.GenerateToken(
		types.Principal{
			UserID:   "user-123",
			TenantID: "tenant-test",
			Username: "testadmin",
			Role:     "admin",
		}, "")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/audit?limit=50", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-ID", "req-test-123")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify DCS was called exactly once
	if enforcer.auditReadCalls != 1 {
		t.Errorf("expected EvaluateAuditRead called once, got %d", enforcer.auditReadCalls)
	}

	// Verify Principal passed to DCS
	if enforcer.lastPrincipal.TenantID != "tenant-test" {
		t.Errorf("expected principal.TenantID='tenant-test', got %q", enforcer.lastPrincipal.TenantID)
	}
	if enforcer.lastPrincipal.UserID != "user-123" {
		t.Errorf("expected principal.UserID='user-123', got %q", enforcer.lastPrincipal.UserID)
	}
	if enforcer.lastPrincipal.Role != "admin" {
		t.Errorf("expected principal.Role='admin', got %q", enforcer.lastPrincipal.Role)
	}

	// Verify RequestContext passed to DCS
	if enforcer.lastRequestContext.RequestID != "req-test-123" {
		t.Errorf("expected requestContext.RequestID='req-test-123', got %q", enforcer.lastRequestContext.RequestID)
	}
	if enforcer.lastRequestContext.Env != "dev" {
		t.Errorf("expected requestContext.Env='dev', got %q", enforcer.lastRequestContext.Env)
	}

	// Verify repository was called with correct tenant
	if auditRepo.lastTenantID != "tenant-test" {
		t.Errorf("expected repo called with tenant_id='tenant-test', got %q", auditRepo.lastTenantID)
	}
	if auditRepo.lastLimit != 50 {
		t.Errorf("expected repo called with limit=50, got %d", auditRepo.lastLimit)
	}
}
