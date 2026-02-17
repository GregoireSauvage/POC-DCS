package service

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type mockAuditService struct {
	writeCalls   int
	lastAuditLog *domain.AuditLog
	allAuditLogs []*domain.AuditLog
	writeError   error
}

func (m *mockAuditService) WriteAudit(ctx context.Context, log *domain.AuditLog) error {
	if m == nil {
		return nil // Graceful handling of nil receiver
	}
	m.writeCalls++
	m.lastAuditLog = log
	m.allAuditLogs = append(m.allAuditLogs, log)
	return m.writeError
}

func (m *mockAuditService) List(ctx context.Context, principal Principal, reqCtx RequestContext, limit int) ([]*domain.AuditLog, error) {
	return nil, errors.New("not implemented in mock")
}

func TestFilmService_List_WritesAudit_AdminDecrypts(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: "encrypted-120"},
		},
	}
	enforcer := defaultPolicyEnforcer()
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "u-admin",
		Username: "admin",
		Role:     "admin",
	}
	reqCtx := RequestContext{
		RequestID: "req-123",
		ClientIP:  "192.168.1.1",
	}

	// Act
	_, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Assert
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected audit written once, got %d", auditSvc.writeCalls)
	}

	audit := auditSvc.lastAuditLog
	if audit == nil {
		t.Fatal("expected audit log to be captured")
	}

	// Verify audit structure
	if audit.Action != "film.read" {
		t.Errorf("expected action=film.read, got %q", audit.Action)
	}
	if audit.ResourceType != "film" {
		t.Errorf("expected resource_type=film, got %q", audit.ResourceType)
	}
	if audit.Outcome != "allow" {
		t.Errorf("expected outcome=allow, got %q", audit.Outcome)
	}

	// Verify context
	if audit.RequestID != "req-123" {
		t.Errorf("expected request_id=req-123, got %q", audit.RequestID)
	}
	if audit.TenantID != "t1" {
		t.Errorf("expected tenant_id=t1, got %q", audit.TenantID)
	}
	if audit.SubjectUserID != "u-admin" {
		t.Errorf("expected subject_user_id=u-admin, got %q", audit.SubjectUserID)
	}
	if audit.SubjectRole != "admin" {
		t.Errorf("expected subject_role=admin, got %q", audit.SubjectRole)
	}

	// Verify field decisions (admin should decrypt time_elapsed)
	if !contains(audit.FieldsDecrypted, "time_elapsed") {
		t.Errorf("expected fields_decrypted to contain 'time_elapsed', got %v", audit.FieldsDecrypted)
	}
	if len(audit.FieldsMasked) != 0 {
		t.Errorf("expected fields_masked to be empty for admin, got %v", audit.FieldsMasked)
	}
	if len(audit.FieldsDenied) != 0 {
		t.Errorf("expected fields_denied to be empty, got %v", audit.FieldsDenied)
	}
}

func TestFilmService_List_WritesAudit_DeveloperMasks(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Inception", TimeElapsedCT: "encrypted-148"},
		},
	}
	enforcer := defaultPolicyEnforcer()
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "u-dev",
		Username: "developer",
		Role:     "developer",
	}
	reqCtx := RequestContext{RequestID: "req-456"}

	// Act
	_, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Assert
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected audit written once, got %d", auditSvc.writeCalls)
	}

	audit := auditSvc.lastAuditLog
	if audit.Action != "film.read" {
		t.Errorf("expected action=film.read, got %q", audit.Action)
	}

	// Verify field decisions (developer should get time_elapsed masked)
	if len(audit.FieldsDecrypted) != 0 {
		t.Errorf("expected fields_decrypted to be empty for developer, got %v", audit.FieldsDecrypted)
	}
	if !contains(audit.FieldsMasked, "time_elapsed") {
		t.Errorf("expected fields_masked to contain 'time_elapsed', got %v", audit.FieldsMasked)
	}
	if len(audit.FieldsDenied) != 0 {
		t.Errorf("expected fields_denied to be empty, got %v", audit.FieldsDenied)
	}

	// Verify role recorded correctly
	if audit.SubjectRole != "developer" {
		t.Errorf("expected subject_role=developer, got %q", audit.SubjectRole)
	}
}

func TestFilmService_List_WritesAudit_EmptyResult(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{}, // No films for this tenant
	}
	enforcer := defaultPolicyEnforcer()
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-empty"}

	// Act
	films, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Assert
	if len(films) != 0 {
		t.Errorf("expected empty films list, got %d", len(films))
	}

	// Audit should still be written even with empty result
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected audit written even for empty result, got %d calls", auditSvc.writeCalls)
	}

	audit := auditSvc.lastAuditLog
	if audit.Action != "film.read" {
		t.Errorf("expected action=film.read, got %q", audit.Action)
	}
	if audit.Outcome != "allow" {
		t.Errorf("expected outcome=allow, got %q", audit.Outcome)
	}

	// Empty result should have empty field decisions
	if len(audit.FieldsDecrypted) != 0 {
		t.Errorf("expected fields_decrypted to be empty, got %v", audit.FieldsDecrypted)
	}
	if len(audit.FieldsMasked) != 0 {
		t.Errorf("expected fields_masked to be empty, got %v", audit.FieldsMasked)
	}
	if len(audit.FieldsDenied) != 0 {
		t.Errorf("expected fields_denied to be empty, got %v", audit.FieldsDenied)
	}
}

func TestFilmService_List_WritesAudit_MultipleFilms(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Film 1", TimeElapsedCT: "encrypted-100"},
			{TenantID: "t1", ID: "film-2", Title: "Film 2", TimeElapsedCT: "encrypted-120"},
			{TenantID: "t1", ID: "film-3", Title: "Film 3", TimeElapsedCT: "encrypted-90"},
		},
	}
	enforcer := defaultPolicyEnforcer()
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-multi"}

	// Act
	films, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Assert
	if len(films) != 3 {
		t.Errorf("expected 3 films, got %d", len(films))
	}

	// Should write ONE audit log for the entire List operation
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected single audit log for List operation, got %d", auditSvc.writeCalls)
	}

	audit := auditSvc.lastAuditLog
	if audit.Action != "film.read" {
		t.Errorf("expected action=film.read, got %q", audit.Action)
	}

	// Field decisions should be aggregated (no duplicates)
	// Admin decrypts time_elapsed for all films → should appear once in fields_decrypted
	if !contains(audit.FieldsDecrypted, "time_elapsed") {
		t.Errorf("expected fields_decrypted to contain 'time_elapsed', got %v", audit.FieldsDecrypted)
	}

	// Verify no duplicates (should be deduplicated)
	if count(audit.FieldsDecrypted, "time_elapsed") > 1 {
		t.Errorf("expected fields_decrypted to be deduplicated, got %v", audit.FieldsDecrypted)
	}
}

func TestFilmService_List_NoAudit_ServiceNil(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Film", TimeElapsedCT: "encrypted-100"},
		},
	}
	enforcer := defaultPolicyEnforcer()
	auditSvc := (*mockAuditService)(nil) // NIL audit service
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-noaudit"}

	// Act - should not panic
	_, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Assert - no panic is success
	t.Log("List succeeded without audit service (graceful degradation)")
}

func TestFilmService_List_AuditError_DoesNotFail(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Film", TimeElapsedCT: "encrypted-100"},
		},
	}
	enforcer := defaultPolicyEnforcer()
	auditSvc := &mockAuditService{
		writeError: errors.New("audit DB unavailable"), // Simulate audit write failure
	}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-error"}

	// Act - should succeed despite audit error
	films, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("List should not fail due to audit error, got: %v", err)
	}

	// Assert
	if len(films) != 1 {
		t.Errorf("expected 1 film, got %d", len(films))
	}

	// Verify audit was attempted
	if auditSvc.writeCalls != 1 {
		t.Errorf("expected audit write attempted, got %d calls", auditSvc.writeCalls)
	}

	t.Log("List succeeded despite audit write error (graceful degradation)")
}

func TestFilmService_UpdateTime_WritesAudit_Allow(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Film", TimeElapsedCT: "old-encrypted"},
		},
	}

	enforcer := &fakePolicyEnforcer{
		evaluateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, filmID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, Reason: "admin allowed"}, nil
		},
		readFunc: defaultFilmReadFunc,
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "u-admin",
		Username: "admin",
		Role:     "admin",
	}
	reqCtx := RequestContext{RequestID: "req-update"}

	// Act
	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "film-1", 150)
	if err != nil {
		t.Fatalf("UpdateTime failed: %v", err)
	}

	// Assert
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected audit written once, got %d", auditSvc.writeCalls)
	}

	audit := auditSvc.lastAuditLog
	if audit == nil {
		t.Fatal("expected audit log to be captured")
	}

	// Verify audit structure
	if audit.Action != "film.update_time" {
		t.Errorf("expected action=film.update_time, got %q", audit.Action)
	}
	if audit.ResourceType != "film" {
		t.Errorf("expected resource_type=film, got %q", audit.ResourceType)
	}
	if audit.ResourceID != "film-1" {
		t.Errorf("expected resource_id=film-1, got %q", audit.ResourceID)
	}
	if audit.Outcome != "allow" {
		t.Errorf("expected outcome=allow, got %q", audit.Outcome)
	}

	// Verify context
	if audit.RequestID != "req-update" {
		t.Errorf("expected request_id=req-update, got %q", audit.RequestID)
	}
	if audit.SubjectUserID != "u-admin" {
		t.Errorf("expected subject_user_id=u-admin, got %q", audit.SubjectUserID)
	}
	if audit.SubjectRole != "admin" {
		t.Errorf("expected subject_role=admin, got %q", audit.SubjectRole)
	}
}

func TestFilmService_UpdateTime_WritesAudit_Deny(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Film", TimeElapsedCT: "encrypted"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		evaluateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, filmID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: false, Reason: "developer not allowed"}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "u-dev",
		Username: "developer",
		Role:     "developer",
	}
	reqCtx := RequestContext{RequestID: "req-deny"}

	// Act - should be forbidden
	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "film-1", 150)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got: %v", err)
	}

	// Assert - audit should be written BEFORE returning error
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected audit written for deny case, got %d calls", auditSvc.writeCalls)
	}

	audit := auditSvc.lastAuditLog
	if audit.Action != "film.update_time" {
		t.Errorf("expected action=film.update_time, got %q", audit.Action)
	}
	if audit.Outcome != "deny" {
		t.Errorf("expected outcome=deny, got %q", audit.Outcome)
	}
	if audit.ResourceID != "film-1" {
		t.Errorf("expected resource_id=film-1, got %q", audit.ResourceID)
	}

	// Verify deny reason captured
	if audit.SubjectRole != "developer" {
		t.Errorf("expected subject_role=developer, got %q", audit.SubjectRole)
	}
}

func TestFilmService_UpdateTime_NoAudit_ServiceNil(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Film", TimeElapsedCT: "encrypted"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		evaluateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, filmID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true}, nil
		},
		readFunc: defaultFilmReadFunc,
	}
	auditSvc := (*mockAuditService)(nil) // NIL audit service
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-noaudit"}

	// Act - should not panic
	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "film-1", 100)
	if err != nil {
		t.Fatalf("UpdateTime failed: %v", err)
	}

	// Assert - no panic is success
	t.Log("UpdateTime succeeded without audit service (graceful degradation)")
}

func TestFilmService_UpdateTime_AuditError_DoesNotFail(t *testing.T) {
	// Setup
	repo := &fakeFilmRepo{
		films: []FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Film", TimeElapsedCT: "encrypted"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		evaluateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, filmID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true}, nil
		},
		readFunc: defaultFilmReadFunc,
	}
	auditSvc := &mockAuditService{
		writeError: errors.New("audit write failed"),
	}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-error"}

	// Act - should succeed despite audit error
	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "film-1", 100)
	if err != nil {
		t.Fatalf("UpdateTime should not fail due to audit error, got: %v", err)
	}

	// Verify audit was attempted
	if auditSvc.writeCalls != 1 {
		t.Errorf("expected audit write attempted, got %d calls", auditSvc.writeCalls)
	}

	t.Log("UpdateTime succeeded despite audit write error (graceful degradation)")
}

// defaultFilmReadFunc is a simple read function for tests that don't need complex enforcement
func defaultFilmReadFunc(_ context.Context, principal Principal, _ RequestContext, _ FilmReadInput) (FilmReadResult, error) {
	if principal.Role == "admin" {
		return FilmReadResult{
			TimeElapsed:     150,
			FieldsDecrypted: []string{"time_elapsed"},
			FieldsMasked:    []string{},
			FieldsDenied:    []string{},
		}, nil
	}
	return FilmReadResult{
		TimeElapsed:     "1***",
		FieldsDecrypted: []string{},
		FieldsMasked:    []string{"time_elapsed"},
		FieldsDenied:    []string{},
	}, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func count(slice []string, item string) int {
	cnt := 0
	for _, s := range slice {
		if s == item {
			cnt++
		}
	}
	return cnt
}
