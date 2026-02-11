package service

import (
	"context"
	"errors"
	"testing"
)

type fakeFilmRepo struct {
	films     []FilmRecord
	listErr   error
	updateErr error
}

func (f *fakeFilmRepo) ListByTenant(_ context.Context, tenantID string) ([]FilmRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]FilmRecord, 0, len(f.films))
	for _, film := range f.films {
		if film.TenantID == tenantID {
			out = append(out, film)
		}
	}
	return out, nil
}

func (f *fakeFilmRepo) UpdateTimeCiphertext(_ context.Context, tenantID, filmID, ciphertext string) (FilmRecord, error) {
	if f.updateErr != nil {
		return FilmRecord{}, f.updateErr
	}
	for i := range f.films {
		if f.films[i].TenantID == tenantID && f.films[i].ID == filmID {
			f.films[i].TimeElapsedCT = ciphertext
			return f.films[i], nil
		}
	}
	return FilmRecord{}, errors.New("not found")
}

type fakeKMS struct {
	encryptValue string
	encryptErr   error
	encryptCalls int
}

func (f *fakeKMS) Encrypt(_ context.Context, _ string) (string, error) {
	f.encryptCalls++
	if f.encryptErr != nil {
		return "", f.encryptErr
	}
	return f.encryptValue, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, _ string) (string, error) {
	return "", nil
}

type fakePolicyEnforcer struct {
	evaluateFunc func(ctx context.Context, principal Principal, reqCtx RequestContext, filmID string) (AuthorizationDecision, error)
	readFunc     func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error)
}

func (f *fakePolicyEnforcer) EvaluateAuditRead(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) (AuthorizationDecision, error) {
	return AuthorizationDecision{Allow: true, Reason: "audit allowed"}, nil
}

func (f *fakePolicyEnforcer) EvaluateFilmUpdateTime(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	filmID string,
) (AuthorizationDecision, error) {
	if f.evaluateFunc == nil {
		return AuthorizationDecision{Allow: false, Reason: "no evaluator"}, nil
	}
	return f.evaluateFunc(ctx, principal, reqCtx, filmID)
}

func (f *fakePolicyEnforcer) EnforceFilmRead(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	film FilmReadInput,
) (FilmReadResult, error) {
	if f.readFunc == nil {
		return FilmReadResult{}, errors.New("no read enforcer")
	}
	return f.readFunc(ctx, principal, reqCtx, film)
}

func buildFilmServiceForTest(repo FilmRepository, kms KMS) *FilmService {
	return NewFilmService(repo, defaultPolicyEnforcer(), kms, nil) // audit service not needed for tests
}

func defaultPolicyEnforcer() *fakePolicyEnforcer {
	return &fakePolicyEnforcer{
		evaluateFunc: func(_ context.Context, principal Principal, _ RequestContext, _ string) (AuthorizationDecision, error) {
			if principal.Role == "admin" {
				return AuthorizationDecision{Allow: true, Reason: "admin write"}, nil
			}
			return AuthorizationDecision{Allow: false, Reason: "not allowed"}, nil
		},
		readFunc: func(_ context.Context, principal Principal, _ RequestContext, _ FilmReadInput) (FilmReadResult, error) {
			if principal.Role == "admin" {
				return FilmReadResult{TimeElapsed: 240}, nil
			}
			return FilmReadResult{TimeElapsed: "1***"}, nil
		},
	}
}

func TestFilmService_List_DeveloperGetsMaskedValue(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kms := &fakeKMS{}
	svc := buildFilmServiceForTest(repo, kms)

	principal := Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := RequestContext{RequestID: "r1", ClientIP: "127.0.0.1"}

	films, perf, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(films) != 1 {
		t.Fatalf("expected one film")
	}
	if films[0].TimeElapsed != "1***" {
		t.Fatalf("expected masked time_elapsed, got %#v", films[0].TimeElapsed)
	}
	if perf.Metrics()["db_ms"] <= 0 {
		t.Fatalf("expected db_ms metric to be recorded")
	}
}

func TestFilmService_UpdateTime_DeveloperForbidden(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:new"}
	svc := buildFilmServiceForTest(repo, kms)

	principal := Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := RequestContext{RequestID: "r2", ClientIP: "127.0.0.1"}

	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden error, got %v", err)
	}
	if kms.encryptCalls != 0 {
		t.Fatalf("encrypt should not be called when forbidden")
	}
}

func TestFilmService_UpdateTime_AdminAllowed(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:new"}
	svc := buildFilmServiceForTest(repo, kms)

	principal := Principal{TenantID: "t1", UserID: "u9", Username: "admin", Role: "admin"}
	reqCtx := RequestContext{RequestID: "r3", ClientIP: "127.0.0.1"}

	film, perf, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if err != nil {
		t.Fatalf("update time failed: %v", err)
	}
	if film.TimeElapsed != 240 {
		t.Fatalf("expected decrypted int 240, got %#v", film.TimeElapsed)
	}
	if kms.encryptCalls != 1 {
		t.Fatalf("expected one encrypt call, got %d", kms.encryptCalls)
	}
	if perf.Metrics()["kms_ms"] <= 0 {
		t.Fatalf("expected kms_ms metric to be recorded")
	}
}

func TestFilmService_List_RepoError(t *testing.T) {
	repoErr := errors.New("db unavailable")
	repo := &fakeFilmRepo{listErr: repoErr}
	svc := buildFilmServiceForTest(repo, &fakeKMS{})

	_, _, err := svc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{})
	if !errors.Is(err, repoErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
}

func TestFilmService_List_EnforcerError(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	enforcerErr := errors.New("pep failure")
	policy := defaultPolicyEnforcer()
	policy.readFunc = func(_ context.Context, _ Principal, _ RequestContext, _ FilmReadInput) (FilmReadResult, error) {
		return FilmReadResult{}, enforcerErr
	}
	svc := NewFilmService(repo, policy, &fakeKMS{}, nil)

	_, _, err := svc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{})
	if !errors.Is(err, enforcerErr) {
		t.Fatalf("expected enforcer error, got %v", err)
	}
}

func TestFilmService_UpdateTime_EvaluateError(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	evalErr := errors.New("pdp failure")
	policy := defaultPolicyEnforcer()
	policy.evaluateFunc = func(_ context.Context, _ Principal, _ RequestContext, _ string) (AuthorizationDecision, error) {
		return AuthorizationDecision{}, evalErr
	}
	kms := &fakeKMS{encryptValue: "vault:v1:new"}
	svc := NewFilmService(repo, policy, kms, nil)

	_, _, err := svc.UpdateTime(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, "f1", 240)
	if !errors.Is(err, evalErr) {
		t.Fatalf("expected evaluate error, got %v", err)
	}
	if kms.encryptCalls != 0 {
		t.Fatalf("encrypt should not be called when evaluation fails")
	}
}

func TestFilmService_UpdateTime_EncryptError(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kmsErr := errors.New("kms unavailable")
	kms := &fakeKMS{encryptErr: kmsErr}
	svc := buildFilmServiceForTest(repo, kms)

	_, _, err := svc.UpdateTime(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, "f1", 240)
	if err == nil {
		t.Fatalf("expected encryption error")
	}
	if !errors.Is(err, kmsErr) {
		t.Fatalf("expected wrapped kms error, got %v", err)
	}
}

func TestFilmService_UpdateTime_RepoErrorWrappedNotFound(t *testing.T) {
	repo := &fakeFilmRepo{
		films:     []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
		updateErr: errors.New("db write failed"),
	}
	svc := buildFilmServiceForTest(repo, &fakeKMS{encryptValue: "vault:v1:new"})

	_, _, err := svc.UpdateTime(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, "f1", 240)
	if err == nil {
		t.Fatalf("expected repository update error")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound wrapper, got %v", err)
	}
}

func TestFilmService_UpdateTime_ReadEnforcerError(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	readErr := errors.New("read enforcement failed")
	policy := defaultPolicyEnforcer()
	policy.readFunc = func(_ context.Context, _ Principal, _ RequestContext, _ FilmReadInput) (FilmReadResult, error) {
		return FilmReadResult{}, readErr
	}
	svc := NewFilmService(repo, policy, &fakeKMS{encryptValue: "vault:v1:new"}, nil)

	_, _, err := svc.UpdateTime(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, "f1", 240)
	if !errors.Is(err, readErr) {
		t.Fatalf("expected read enforcer error, got %v", err)
	}
}
