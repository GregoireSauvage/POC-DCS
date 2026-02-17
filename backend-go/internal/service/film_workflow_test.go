package service

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
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

func (f *fakeFilmRepo) Create(_ context.Context, tenantID, title, timeElapsedCT string) (FilmRecord, error) {
	// Stub implementation - not used in most tests
	return FilmRecord{}, nil
}

type fakePolicyEnforcer struct{
	evaluateFunc                func(ctx context.Context, principal Principal, reqCtx RequestContext, filmID string) (AuthorizationDecision, error)
	evaluateCreateFunc          func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error)
	readFunc                    func(ctx context.Context, principal Principal, reqCtx RequestContext, film FilmReadInput) (FilmReadResult, error)
	enforceFilmCreateFunc       func(ctx context.Context, principal Principal, reqCtx RequestContext, input FilmCreatePlain) (FilmCreateEncrypted, error)
	evaluateSpectatorCreateFunc func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error)
	evaluateSpectatorSearchFunc func(ctx context.Context, principal Principal, reqCtx RequestContext) (AuthorizationDecision, error)
	enforceSpectatorReadFunc    func(ctx context.Context, principal Principal, reqCtx RequestContext, spectator SpectatorReadInput) (SpectatorReadResult, error)
	enforceSpectatorCreateFunc  func(ctx context.Context, principal Principal, reqCtx RequestContext, input SpectatorCreatePlain) (SpectatorCreateEncrypted, error)
	getPepperFunc               func(ctx context.Context, path string) ([]byte, error)
	encryptFunc                 func(ctx context.Context, plaintext string) (string, error)
	decryptFunc                 func(ctx context.Context, ciphertext string) (string, error)
}

func (f *fakePolicyEnforcer) EvaluateAuditRead(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) (AuthorizationDecision, error) {
	return AuthorizationDecision{Allow: true, Reason: "audit allowed"}, nil
}

func (f *fakePolicyEnforcer) EvaluatePerfRead(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) (AuthorizationDecision, error) {
	return AuthorizationDecision{Allow: true, Reason: "perf allowed"}, nil
}

func (f *fakePolicyEnforcer) EvaluateFilmCreate(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) (AuthorizationDecision, error) {
	if f.evaluateCreateFunc == nil {
		return AuthorizationDecision{Allow: false, Reason: "no create evaluator"}, nil
	}
	return f.evaluateCreateFunc(ctx, principal, reqCtx)
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

// Hall policy stubs (not used in film tests)
func (f *fakePolicyEnforcer) EvaluateHallCreate(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	ownerUserID string,
) (AuthorizationDecision, error) {
	return AuthorizationDecision{Allow: true, Reason: "test"}, nil
}

func (f *fakePolicyEnforcer) EvaluateHallRead(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	hallID string,
	ownerUserID string,
) (AuthorizationDecision, error) {
	return AuthorizationDecision{Allow: true, Reason: "test"}, nil
}

func (f *fakePolicyEnforcer) EnforceHallRead(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	hall HallReadInput,
) (HallReadResult, error) {
	return HallReadResult{}, nil
}

// Spectator policy stubs
func (f *fakePolicyEnforcer) EvaluateSpectatorCreate(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	ownerUserID string,
) (AuthorizationDecision, error) {
	if f.evaluateSpectatorCreateFunc != nil {
		return f.evaluateSpectatorCreateFunc(ctx, principal, reqCtx, ownerUserID)
	}
	return AuthorizationDecision{Allow: true, Reason: "test"}, nil
}

func (f *fakePolicyEnforcer) EvaluateSpectatorSearch(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) (AuthorizationDecision, error) {
	if f.evaluateSpectatorSearchFunc != nil {
		return f.evaluateSpectatorSearchFunc(ctx, principal, reqCtx)
	}
	return AuthorizationDecision{Allow: true, Reason: "test"}, nil
}

func (f *fakePolicyEnforcer) EnforceSpectatorRead(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	spectator SpectatorReadInput,
) (SpectatorReadResult, error) {
	if f.enforceSpectatorReadFunc != nil {
		return f.enforceSpectatorReadFunc(ctx, principal, reqCtx, spectator)
	}
	return SpectatorReadResult{}, nil
}

// Crypto delegation stubs
func (f *fakePolicyEnforcer) Encrypt(ctx context.Context, plaintext string) (string, error) {
	if f.encryptFunc != nil {
		return f.encryptFunc(ctx, plaintext)
	}
	return "encrypted-" + plaintext, nil
}

func (f *fakePolicyEnforcer) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	if f.decryptFunc != nil {
		return f.decryptFunc(ctx, ciphertext)
	}
	return "decrypted", nil
}

func (f *fakePolicyEnforcer) GetPepper(ctx context.Context, path string) ([]byte, error) {
	if f.getPepperFunc != nil {
		return f.getPepperFunc(ctx, path)
	}
	return []byte("test-pepper"), nil
}

// Enforce create stubs
func (f *fakePolicyEnforcer) EnforceFilmCreate(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	input FilmCreatePlain,
) (FilmCreateEncrypted, error) {
	if f.enforceFilmCreateFunc != nil {
		return f.enforceFilmCreateFunc(ctx, principal, reqCtx, input)
	}
	// Check authorization first if evaluateCreateFunc is set
	if f.evaluateCreateFunc != nil {
		decision, err := f.evaluateCreateFunc(ctx, principal, reqCtx)
		if err != nil {
			return FilmCreateEncrypted{}, err
		}
		if !decision.Allow {
			return FilmCreateEncrypted{}, ErrForbidden
		}
	}
	return FilmCreateEncrypted{
		Title:         input.Title,
		TimeElapsedCT: "vault:v1:encrypted",
	}, nil
}

func (f *fakePolicyEnforcer) EnforceSpectatorCreate(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	input SpectatorCreatePlain,
) (SpectatorCreateEncrypted, error) {
	if f.enforceSpectatorCreateFunc != nil {
		return f.enforceSpectatorCreateFunc(ctx, principal, reqCtx, input)
	}
	// Check authorization first if evaluateSpectatorCreateFunc is set
	if f.evaluateSpectatorCreateFunc != nil {
		decision, err := f.evaluateSpectatorCreateFunc(ctx, principal, reqCtx, "")
		if err != nil {
			return SpectatorCreateEncrypted{}, err
		}
		if !decision.Allow {
			return SpectatorCreateEncrypted{}, ErrForbidden
		}
	}
	return SpectatorCreateEncrypted{
		HallID:           input.HallID,
		NameCT:           "vault:v1:encrypted",
		AgeCT:            "vault:v1:encrypted",
		ExternalIDCT:     "vault:v1:encrypted",
		ExternalIDLookup: []byte("hmac-lookup"),
	}, nil
}

type fakePerfWriter struct {
	calls   int
	lastLog *domain.PerfLog
	err     error
}

func (f *fakePerfWriter) Write(ctx context.Context, log *domain.PerfLog) error {
	_ = ctx
	f.calls++
	f.lastLog = log
	return f.err
}

type fakeRuntimeSettings struct {
	dcsEnabled bool
	cacheLevel int
}

func (f fakeRuntimeSettings) DcsEnabled() bool { return f.dcsEnabled }
func (f fakeRuntimeSettings) CacheLevel() int { return f.cacheLevel }

func buildFilmServiceForTest(repo FilmRepository) *FilmService {
	return NewFilmService(repo, defaultPolicyEnforcer(), nil, nil, nil) // audit service not needed for tests
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
				return FilmReadResult{
					TimeElapsed:     240,
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
		},
	}
}

func TestFilmService_List_DeveloperGetsMaskedValue(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	svc := buildFilmServiceForTest(repo)

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
	svc := buildFilmServiceForTest(repo)

	principal := Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := RequestContext{RequestID: "r2", ClientIP: "127.0.0.1"}

	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden error, got %v", err)
	}
	// Note: Encryption now handled by enforcer (not called on forbidden)
}

func TestFilmService_UpdateTime_AdminAllowed(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	svc := buildFilmServiceForTest(repo)

	principal := Principal{TenantID: "t1", UserID: "u9", Username: "admin", Role: "admin"}
	reqCtx := RequestContext{RequestID: "r3", ClientIP: "127.0.0.1"}

	film, perf, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if err != nil {
		t.Fatalf("update time failed: %v", err)
	}
	if film.TimeElapsed != 240 {
		t.Fatalf("expected decrypted int 240, got %#v", film.TimeElapsed)
	}
	// Note: Encryption now handled by enforcer
	if perf.Metrics()["kms_ms"] <= 0 {
		t.Fatalf("expected kms_ms metric to be recorded")
	}
}

func TestFilmService_List_RepoError(t *testing.T) {
	repoErr := errors.New("db unavailable")
	repo := &fakeFilmRepo{listErr: repoErr}
	svc := buildFilmServiceForTest(repo)

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
	svc := NewFilmService(repo, policy, nil, nil, nil)

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
	svc := NewFilmService(repo, policy, nil, nil, nil)

	_, _, err := svc.UpdateTime(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, "f1", 240)
	if !errors.Is(err, evalErr) {
		t.Fatalf("expected evaluate error, got %v", err)
	}
	// Note: We no longer verify encrypt calls since KMS is internal to enforcer
}

func TestFilmService_UpdateTime_EncryptError(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kmsErr := errors.New("kms unavailable")
	policy := &fakePolicyEnforcer{
		evaluateFunc: func(_ context.Context, principal Principal, _ RequestContext, _ string) (AuthorizationDecision, error) {
			if principal.Role == "admin" {
				return AuthorizationDecision{Allow: true, Reason: "admin write"}, nil
			}
			return AuthorizationDecision{Allow: false, Reason: "forbidden"}, nil
		},
		encryptFunc: func(_ context.Context, _ string) (string, error) {
			return "", kmsErr
		},
	}
	svc := NewFilmService(repo, policy, nil, nil, nil)

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
	svc := buildFilmServiceForTest(repo)

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
	svc := NewFilmService(repo, policy, nil, nil, nil)

	_, _, err := svc.UpdateTime(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, "f1", 240)
	if !errors.Is(err, readErr) {
		t.Fatalf("expected read enforcer error, got %v", err)
	}
}

func TestFilmService_List_WritesPerfLog(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}
	svc := NewFilmService(repo, defaultPolicyEnforcer(), nil, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := RequestContext{RequestID: "req-123", ClientIP: "127.0.0.1"}

	_, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}

	if perfWriter.calls != 1 {
		t.Fatalf("expected perf writer called once, got %d", perfWriter.calls)
	}
	log := perfWriter.lastLog
	if log == nil {
		t.Fatal("expected perf log captured")
	}
	if log.Action != "film.read" || log.ResourceType != "film" {
		t.Fatalf("unexpected action/resource: %s/%s", log.Action, log.ResourceType)
	}
	if log.RequestID != "req-123" || log.TenantID != "t1" {
		t.Fatalf("unexpected request/tenant: %s/%s", log.RequestID, log.TenantID)
	}
	if log.SubjectUserID != "u1" || log.SubjectRole != "developer" {
		t.Fatalf("unexpected subject fields: %s/%s", log.SubjectUserID, log.SubjectRole)
	}
	if !log.DCSEnabled || log.CacheLevel != 2 {
		t.Fatalf("unexpected dcs/cache: %v/%d", log.DCSEnabled, log.CacheLevel)
	}
	if log.DBMS == nil {
		t.Fatalf("expected db_ms to be recorded")
	}
}

func TestFilmService_UpdateTime_WritesPerfLog(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 1}
	svc := NewFilmService(repo, defaultPolicyEnforcer(), nil, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u9", Username: "admin", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-999", ClientIP: "127.0.0.1"}

	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if err != nil {
		t.Fatalf("update time failed: %v", err)
	}

	if perfWriter.calls != 1 {
		t.Fatalf("expected perf writer called once, got %d", perfWriter.calls)
	}
	log := perfWriter.lastLog
	if log == nil {
		t.Fatal("expected perf log captured")
	}
	if log.Action != "film.update_time" || log.ResourceType != "film" {
		t.Fatalf("unexpected action/resource: %s/%s", log.Action, log.ResourceType)
	}
	if log.RequestID != "req-999" || log.TenantID != "t1" {
		t.Fatalf("unexpected request/tenant: %s/%s", log.RequestID, log.TenantID)
	}
	if log.SubjectUserID != "u9" || log.SubjectRole != "admin" {
		t.Fatalf("unexpected subject fields: %s/%s", log.SubjectUserID, log.SubjectRole)
	}
	if !log.DCSEnabled || log.CacheLevel != 1 {
		t.Fatalf("unexpected dcs/cache: %v/%d", log.DCSEnabled, log.CacheLevel)
	}
	if log.KMSMS == nil {
		t.Fatalf("expected kms_ms to be recorded")
	}
	if log.DBMS == nil {
		t.Fatalf("expected db_ms to be recorded")
	}
}

func TestFilmService_UpdateTime_Forbidden_DoesNotWritePerfLog(t *testing.T) {
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 1}
	svc := NewFilmService(repo, defaultPolicyEnforcer(), nil, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := RequestContext{RequestID: "req-777", ClientIP: "127.0.0.1"}

	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden error, got %v", err)
	}
	if perfWriter.calls != 0 {
		t.Fatalf("expected perf writer not called on forbidden")
	}
}
