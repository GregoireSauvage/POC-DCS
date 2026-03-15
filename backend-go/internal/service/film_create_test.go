package service

import (
	"context"
	"errors"
	"testing"
)

type fakeFilmRepoWithCreate struct {
	*fakeFilmRepo
	createResult FilmRecord
	createView   FilmReadView
	createError  error
	createCalls  int
}

func (f *fakeFilmRepoWithCreate) Create(ctx context.Context, tenantID, title, timeElapsedCT string) (FilmReadView, error) {
	f.createCalls++
	if f.createError != nil {
		return FilmReadView{}, f.createError
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
	if f.createView.Output.ID != "" || f.createView.Output.Title != "" || f.createView.Output.TimeElapsed != nil || len(f.createView.FieldsDecrypted) > 0 || len(f.createView.FieldsMasked) > 0 || len(f.createView.FieldsDenied) > 0 {
		view := f.createView
		if view.Output.ID == "" {
			view.Output.ID = result.ID
		}
		if view.Output.Title == "" {
			view.Output.Title = result.Title
		}
		return view, nil
	}
	return f.fakeFilmRepo.buildView(ctx, result)
}

func TestFilmService_Create_AdminAllowed_Decrypted(t *testing.T) {
	// Arrange
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createResult: FilmRecord{
			ID:            "film-123",
			Title:         "Matrix",
			TimeElapsedCT: "vault:v1:encrypted",
		},
		createView: FilmReadView{
			Output: FilmOutput{
				ID:          "film-123",
				Title:       "Matrix",
				TimeElapsed: 136,
			},
			FieldsDecrypted: []string{"time_elapsed"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			// Authorize and encrypt
			return FilmCreateEncrypted{
				Title:         input.Title,
				TimeElapsedCT: "vault:v1:encrypted",
			}, nil
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

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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
	// Note: In integrated PDP+PEP architecture, decision hash not available on allow path
	// (only available via ForbiddenError on deny path)

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
		createView: FilmReadView{
			Output: FilmOutput{
				ID:          "film-456",
				Title:       "Inception",
				TimeElapsed: 148,
			},
			FieldsDecrypted: []string{"time_elapsed"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			// Agent authorized to create
			return FilmCreateEncrypted{
				Title:         input.Title,
				TimeElapsedCT: "vault:v1:encrypted",
			}, nil
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

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			if principal.Role == "developer" {
				return FilmCreateEncrypted{}, ErrForbidden
			}
			return FilmCreateEncrypted{
				Title:         input.Title,
				TimeElapsedCT: "vault:v1:encrypted",
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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

	// Check audit WRITTEN (deny case)
	if auditSvc.writeCalls != 1 {
		t.Fatalf("expected 1 audit call (deny), got %d", auditSvc.writeCalls)
	}
	audit := auditSvc.lastAuditLog
	if audit.Outcome != "deny" {
		t.Errorf("expected outcome=deny, got %q", audit.Outcome)
	}
	if audit.DecisionHash != "" {
		t.Errorf("expected empty decision_hash on deny, got %q", audit.DecisionHash)
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
		createView: FilmReadView{
			Output: FilmOutput{
				ID:          "film-789",
				Title:       "Short",
				TimeElapsed: 0,
			},
			FieldsDecrypted: []string{"time_elapsed"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			return FilmCreateEncrypted{
				Title:         input.Title,
				TimeElapsedCT: "vault:v1:encrypted",
			}, nil
		},
		readFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error) {
			return FilmReadResult{TimeElapsed: 0, FieldsDecrypted: []string{"time_elapsed"}}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			return FilmCreateEncrypted{}, errors.New("encrypt time_elapsed: vault unavailable")
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			return FilmCreateEncrypted{
				Title:         input.Title,
				TimeElapsedCT: "vault:v1:encrypted",
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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
}

func TestFilmService_Create_AuditError_DoesNotFail(t *testing.T) {
	// Audit write fails but request succeeds (graceful degradation)
	repo := &fakeFilmRepoWithCreate{
		fakeFilmRepo: &fakeFilmRepo{},
		createResult: FilmRecord{ID: "film-ok", Title: "OK", TimeElapsedCT: "vault:v1:ok"},
		createView: FilmReadView{
			Output: FilmOutput{
				ID:          "film-ok",
				Title:       "OK",
				TimeElapsed: 100,
			},
			FieldsDecrypted: []string{"time_elapsed"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			return FilmCreateEncrypted{
				Title:         input.Title,
				TimeElapsedCT: "vault:v1:encrypted",
			}, nil
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

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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
		createView: FilmReadView{
			Output: FilmOutput{
				ID:          "film-no-audit",
				Title:       "NoAudit",
				TimeElapsed: 90,
			},
			FieldsDecrypted: []string{"time_elapsed"},
		},
	}
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			return FilmCreateEncrypted{
				Title:         input.Title,
				TimeElapsedCT: "vault:v1:encrypted",
			}, nil
		},
		readFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error) {
			return FilmReadResult{TimeElapsed: 90, FieldsDecrypted: []string{"time_elapsed"}}, nil
		},
	}

	svc := NewFilmService(repo, enforcer, nil, nil, nil) // nil audit, perf, runtime

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
	enforcer := &fakePolicyEnforcer{
		enforceFilmCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error) {
			return FilmCreateEncrypted{}, errors.New("PDP unreachable")
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true}

	svc := NewFilmService(repo, enforcer, auditSvc, perfWriter, runtime)

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
