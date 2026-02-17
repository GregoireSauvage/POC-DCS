package service

import (
	"context"
	"errors"
	"testing"
)

// ============================================================================
// Test Data & Helpers
// ============================================================================

type fakeFilmRepoWithCreate struct {
	*fakeFilmRepo
	createResult FilmRecord
	createError  error
	createCalls  int
}

func (f *fakeFilmRepoWithCreate) Create(ctx context.Context, tenantID, title, timeElapsedCT string) (FilmRecord, error) {
	f.createCalls++
	if f.createError != nil {
		return FilmRecord{}, f.createError
	}
	// Simulate DB behavior: return record with generated ID
	result := f.createResult
	if result.TenantID == "" {
		result.TenantID = tenantID
	}
	if result.Title == "" {
		result.Title = title
	}
	if result.TimeElapsedCT == "" {
		result.TimeElapsedCT = timeElapsedCT
	}
	if result.ID == "" {
		result.ID = "generated-uuid-123"
	}
	return result, nil
}

// ============================================================================
// POST /films - Create Film Tests
// ============================================================================

func TestFilmService_Create_AdminAllowed_Decrypted(t *testing.T) {
	// Arrange
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createResult: FilmRecord{
			ID:            "film-123",
			Title:         "Matrix",
			TimeElapsedCT: "vault:v1:encrypted",
		},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:encrypted"}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			if principal.Role == "admin" {
				return AuthorizationDecision{
					Allow:        true,
					Reason:       "admin_allowed",
					DecisionHash: "hash123",
				}, nil
			}
			return AuthorizationDecision{Allow: false, Reason: "denied"}, nil
		},
		readFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error) {
			// Admin sees decrypted value
			return FilmReadResult{
				TimeElapsed:     136,
				FieldsDecrypted: []string{"time_elapsed"},
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "u-admin",
		Username: "admin",
		Role:     "admin",
	}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	film, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "Matrix",
		TimeElapsed: 136,
	})

	// Assert
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Check response
	if film.Title != "Matrix" {
		t.Errorf("expected title=Matrix, got %q", film.Title)
	}
	if film.TimeElapsed != 136 {
		t.Errorf("expected time_elapsed=136 (decrypted), got %v", film.TimeElapsed)
	}

	// Check KMS called
	if kms.encryptCalls != 1 {
		t.Errorf("expected 1 encrypt call, got %d", kms.encryptCalls)
	}

	// Check repo called
	if repo.createCalls != 1 {
		t.Errorf("expected 1 repo create call, got %d", repo.createCalls)
	}

	// Check audit log
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected 1 audit call, got %d", auditSvc.writeCalls)
	}
	audit := auditSvc.lastAuditLog
	if audit.Action != "film.create" {
		t.Errorf("expected action=film.create, got %q", audit.Action)
	}
	if audit.Outcome != "allow" {
		t.Errorf("expected outcome=allow, got %q", audit.Outcome)
	}
	if audit.DecisionHash == "" {
		t.Error("expected decision_hash to be set")
	}

	// Check perf log
	if perfWriter.calls != 1 {
		t.Errorf("expected 1 perf call, got %d", perfWriter.calls)
	}
}

func TestFilmService_Create_AgentAllowed_Decrypted(t *testing.T) {
	// Agent can create and sees SENSITIVE fields decrypted
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createResult: FilmRecord{ID: "film-456", Title: "Inception", TimeElapsedCT: "vault:v1:enc"},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:enc"}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			if principal.Role == "agent" || principal.Role == "admin" {
				return AuthorizationDecision{
					Allow:        true,
					Reason:       "agent_allowed",
					DecisionHash: "hash-agent",
				}, nil
			}
			return AuthorizationDecision{Allow: false, Reason: "denied"}, nil
		},
		readFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error) {
			// Agent sees SENSITIVE decrypted (not masked!)
			return FilmReadResult{
				TimeElapsed:     148,
				FieldsDecrypted: []string{"time_elapsed"},
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u-agent", Role: "agent"}
	reqCtx := RequestContext{RequestID: "req-456"}

	// Act
	film, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "Inception",
		TimeElapsed: 148,
	})

	// Assert
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Agent sees decrypted (not masked)
	if film.TimeElapsed != 148 {
		t.Errorf("expected time_elapsed=148 (decrypted for agent), got %v", film.TimeElapsed)
	}

	// Check audit
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected 1 audit call, got %d", auditSvc.writeCalls)
	}
	if auditSvc.lastAuditLog.Outcome != "allow" {
		t.Errorf("expected outcome=allow, got %q", auditSvc.lastAuditLog.Outcome)
	}
}

func TestFilmService_Create_DeveloperForbidden(t *testing.T) {
	// Developer cannot create films (write_actions restricted)
	repo := &fakeFilmRepoWithCreate{fakeFilmRepo: &fakeFilmRepo{}}
	kms := &fakeKMS{}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			// Only agent/admin allowed for write_actions
			if principal.Role == "developer" {
				return AuthorizationDecision{
					Allow:        false,
					Reason:       "write_forbidden",
					DecisionHash: "hash-deny",
				}, nil
			}
			return AuthorizationDecision{Allow: true}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u-dev", Role: "developer"}
	reqCtx := RequestContext{RequestID: "req-deny"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "Forbidden",
		TimeElapsed: 100,
	})

	// Assert
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}

	// Check NO repo call
	if repo.createCalls != 0 {
		t.Errorf("expected 0 repo calls (denied before DB), got %d", repo.createCalls)
	}

	// Check NO encrypt call
	if kms.encryptCalls != 0 {
		t.Errorf("expected 0 encrypt calls (denied before encrypt), got %d", kms.encryptCalls)
	}

	// Check audit WRITTEN (deny case)
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected 1 audit call (deny), got %d", auditSvc.writeCalls)
	}
	audit := auditSvc.lastAuditLog
	if audit.Outcome != "deny" {
		t.Errorf("expected outcome=deny, got %q", audit.Outcome)
	}
	if audit.DecisionHash == "" {
		t.Error("expected decision_hash even on deny")
	}
	if audit.Details == nil || audit.Details["reason"] != "write_forbidden" {
		t.Errorf("expected details with reason, got %v", audit.Details)
	}

	// Check perf log WRITTEN (critical: must write even on deny)
	if perfWriter.calls != 1 {
		t.Errorf("expected 1 perf call (even on deny), got %d", perfWriter.calls)
	}
}

func TestFilmService_Create_DefaultTimeElapsed(t *testing.T) {
	// Test default time_elapsed=0 (Python parity)
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createResult: FilmRecord{ID: "film-789", Title: "Short", TimeElapsedCT: "vault:v1:zero"},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:zero"}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
		readFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error) {
			return FilmReadResult{TimeElapsed: 0, FieldsDecrypted: []string{"time_elapsed"}}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-default"}

	// Act - time_elapsed=0 (default)
	film, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "Short",
		TimeElapsed: 0, // Default value
	})

	// Assert
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if film.TimeElapsed != 0 {
		t.Errorf("expected time_elapsed=0, got %v", film.TimeElapsed)
	}
}

func TestFilmService_Create_EncryptError(t *testing.T) {
	// Vault unavailable during encrypt
	repo := &fakeFilmRepoWithCreate{fakeFilmRepo: &fakeFilmRepo{}}
	kms := &fakeKMS{encryptErr: errors.New("vault unavailable")}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-err"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "Error",
		TimeElapsed: 100,
	})

	// Assert
	if err == nil {
		t.Fatal("expected error from encrypt")
	}
	if !errors.Is(err, kms.encryptErr) && err.Error() != "encrypt time_elapsed: vault unavailable" {
		t.Errorf("expected encrypt error, got %v", err)
	}

	// No repo call (error before DB)
	if repo.createCalls != 0 {
		t.Errorf("expected 0 repo calls, got %d", repo.createCalls)
	}
}

func TestFilmService_Create_RepoError(t *testing.T) {
	// DB insert fails
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createError:  errors.New("db connection lost"),
	}
	kms := &fakeKMS{encryptValue: "vault:v1:ok"}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-repo-err"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "DBError",
		TimeElapsed: 100,
	})

	// Assert
	if err == nil {
		t.Fatal("expected error from repo")
	}
	if err.Error() != "create film: db connection lost" {
		t.Errorf("expected repo error, got %v", err)
	}

	// Encrypt was called
	if kms.encryptCalls != 1 {
		t.Errorf("expected encrypt call, got %d", kms.encryptCalls)
	}
}

func TestFilmService_Create_AuditError_DoesNotFail(t *testing.T) {
	// Audit write fails but request succeeds (graceful degradation)
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createResult: FilmRecord{ID: "film-ok", Title: "OK", TimeElapsedCT: "vault:v1:ok"},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:ok"}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
		readFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error) {
			return FilmReadResult{TimeElapsed: 100, FieldsDecrypted: []string{"time_elapsed"}}, nil
		},
	}
	auditSvc := &mockAuditService{
		writeError: errors.New("audit DB unavailable"),
	}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-audit-err"}

	// Act - should succeed despite audit error
	film, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "OK",
		TimeElapsed: 100,
	})

	// Assert
	if err != nil {
		t.Fatalf("Create should not fail due to audit error, got: %v", err)
	}
	if film.Title != "OK" {
		t.Errorf("expected film created, got %q", film.Title)
	}

	// Audit was attempted
	if auditSvc.writeCalls != 1 {
		t.Errorf("expected audit write attempted, got %d", auditSvc.writeCalls)
	}
}

func TestFilmService_Create_NilAuditService(t *testing.T) {
	// No audit service configured (graceful degradation)
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createResult: FilmRecord{ID: "film-no-audit", Title: "NoAudit", TimeElapsedCT: "vault:v1:ok"},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:ok"}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
		readFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error) {
			return FilmReadResult{TimeElapsed: 90, FieldsDecrypted: []string{"time_elapsed"}}, nil
		},
	}

	svc := NewFilmService(repo, enforcer, kms, nil, nil, nil) // nil audit, perf, runtime

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-no-audit"}

	// Act - should not panic
	film, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "NoAudit",
		TimeElapsed: 90,
	})

	// Assert
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if film.Title != "NoAudit" {
		t.Errorf("expected film created, got %q", film.Title)
	}
}

func TestFilmService_Create_EnforcerError(t *testing.T) {
	// Policy evaluation fails
	repo := &fakeFilmRepoWithCreate{fakeFilmRepo: &fakeFilmRepo{}}
	kms := &fakeKMS{}
	enforcer := &fakePolicyEnforcer{
		evaluateCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error) {
			return AuthorizationDecision{}, errors.New("PDP unreachable")
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, kms, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-enforcer-err"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, FilmCreateInput{
		Title:       "Error",
		TimeElapsed: 100,
	})

	// Assert
	if err == nil {
		t.Fatal("expected error from enforcer")
	}
	if err.Error() != "PDP unreachable" {
		t.Errorf("expected enforcer error, got %v", err)
	}
}
