package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// Test 1: Admin lists halls - sees all fields decrypted
func TestHallService_List_AdminSeesAllFields(t *testing.T) {
	repo := &fakeHallRepo{
		halls: []HallRecord{
			{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
		},
	}
	enforcer := &fakeHallLegacyRules{
		readResult: HallReadResult{
			Name:          stringPtr("Hall A"),
			OwnerUserID:   "u-admin",
			CurrentFilmID: "film-1",
			FieldsMasked:  []string{},
			FieldsDenied:  []string{},
		},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	principal := Principal{TenantID: "t1", UserID: "u-admin", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-1"}

	halls, pctx, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(halls) != 1 {
		t.Fatalf("expected 1 hall, got %d", len(halls))
	}

	h := halls[0]
	if h.Name == nil || *h.Name != "Hall A" {
		t.Errorf("expected name='Hall A', got %v", h.Name)
	}
	if h.OwnerUserID != "u-admin" {
		t.Errorf("expected owner_user_id='u-admin', got %v", h.OwnerUserID)
	}
	if h.CurrentFilmID != "film-1" {
		t.Errorf("expected current_film_id='film-1', got %v", h.CurrentFilmID)
	}
	if pctx == nil {
		t.Error("expected perf context to be returned")
	}
}

// Test 2: Developer lists halls - INTERNAL fields masked
func TestHallService_List_DeveloperSeesMaskedINTERNAL(t *testing.T) {
	repo := &fakeHallRepo{
		halls: []HallRecord{
			{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-owner-12345", CurrentFilmID: "film-uuid-67890"},
		},
	}
	enforcer := &fakeHallLegacyRules{
		readResult: HallReadResult{
			Name:          stringPtr("Hall A"),
			OwnerUserID:   "u-ow…", // Masked
			CurrentFilmID: "film…", // Masked
			FieldsMasked:  []string{"owner_user_id", "current_film_id"},
			FieldsDenied:  []string{},
		},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	principal := Principal{TenantID: "t1", UserID: "u-dev", Role: "developer"}
	reqCtx := RequestContext{RequestID: "req-2"}

	halls, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(halls) != 1 {
		t.Fatalf("expected 1 hall, got %d", len(halls))
	}

	h := halls[0]
	if h.Name == nil || *h.Name != "Hall A" {
		t.Errorf("expected name='Hall A', got %v", h.Name)
	}
	if h.OwnerUserID != "u-ow…" {
		t.Errorf("expected masked owner_user_id, got %v", h.OwnerUserID)
	}
	if h.CurrentFilmID != "film…" {
		t.Errorf("expected masked current_film_id, got %v", h.CurrentFilmID)
	}
}

// Test 3: Agent lists halls - INTERNAL fields visible (not masked)
func TestHallService_List_AgentSeesINTERNAL(t *testing.T) {
	repo := &fakeHallRepo{
		halls: []HallRecord{
			{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-owner", CurrentFilmID: "film-1"},
		},
	}
	enforcer := &fakeHallLegacyRules{
		readResult: HallReadResult{
			Name:          stringPtr("Hall A"),
			OwnerUserID:   "u-owner",
			CurrentFilmID: "film-1",
			FieldsMasked:  []string{},
			FieldsDenied:  []string{},
		},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	principal := Principal{TenantID: "t1", UserID: "u-agent", Role: "agent"}
	reqCtx := RequestContext{}

	halls, _, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	h := halls[0]
	if h.OwnerUserID != "u-owner" {
		t.Errorf("agent should see INTERNAL fields, got %v", h.OwnerUserID)
	}
}

// Test 4: Empty halls returns empty array
func TestHallService_List_EmptyHalls(t *testing.T) {
	repo := &fakeHallRepo{halls: []HallRecord{}}
	enforcer := &fakeHallLegacyRules{}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	halls, _, err := svc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(halls) != 0 {
		t.Errorf("expected empty array, got %d halls", len(halls))
	}
}

// Test 5: Repository error propagates
func TestHallService_List_RepoError(t *testing.T) {
	repoErr := errors.New("db unavailable")
	repo := &fakeHallRepo{listErr: repoErr}
	svc := newHallServiceFromLegacyRules(repo, &fakeHallLegacyRules{}, nil, nil, nil)

	_, _, err := svc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{})
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repository error, got %v", err)
	}
}

// Test 6: Enforcer error propagates
func TestHallService_List_EnforcerError(t *testing.T) {
	repo := &fakeHallRepo{
		halls: []HallRecord{{TenantID: "t1", ID: "hall-1", Name: "Hall A"}},
	}
	enforcerErr := errors.New("pep failure")
	enforcer := &fakeHallLegacyRules{readErr: enforcerErr}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	_, _, err := svc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{})
	if !errors.Is(err, enforcerErr) {
		t.Errorf("expected enforcer error, got %v", err)
	}
}

// Test 7: Spectator count is computed per hall
func TestHallService_List_SpectatorCountComputed(t *testing.T) {
	repo := &fakeHallRepo{
		halls: []HallRecord{
			{TenantID: "t1", ID: "hall-1", Name: "Hall A"},
		},
		spectatorCounts: map[string]int{"hall-1": 42},
	}
	enforcer := &fakeHallLegacyRules{
		readResult: HallReadResult{Name: stringPtr("Hall A"), OwnerUserID: "u1", CurrentFilmID: "f1"},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	halls, _, err := svc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if halls[0].SpectatorCount != 42 {
		t.Errorf("expected spectator_count=42, got %d", halls[0].SpectatorCount)
	}
}

// ==================== CREATE TESTS ====================

// Test 8: Admin creates hall successfully
func TestHallService_Create_AdminAllowed(t *testing.T) {
	repo := &fakeHallRepo{}
	enforcer := &fakeHallLegacyRules{
		createDecision: Decision{Allow: true, Reason: "admin write"},
		readResult:     HallReadResult{Name: stringPtr("Hall A"), OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	principal := Principal{TenantID: "t1", UserID: "u-admin", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-create-1"}
	input := HallCreateInput{Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}

	hall, pctx, err := svc.Create(context.Background(), principal, reqCtx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if hall.Name == nil || *hall.Name != "Hall A" {
		t.Errorf("expected name='Hall A', got %v", hall.Name)
	}
	if pctx == nil {
		t.Error("expected perf context")
	}
}

// Test 9: Agent creates hall successfully
func TestHallService_Create_AgentAllowed(t *testing.T) {
	repo := &fakeHallRepo{}
	enforcer := &fakeHallLegacyRules{
		createDecision: Decision{Allow: true, Reason: "agent write"},
		readResult:     HallReadResult{Name: stringPtr("Hall B"), OwnerUserID: "u-agent", CurrentFilmID: "film-2"},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	principal := Principal{TenantID: "t1", UserID: "u-agent", Role: "agent"}
	reqCtx := RequestContext{}
	input := HallCreateInput{Name: "Hall B", OwnerUserID: "u-agent", CurrentFilmID: "film-2"}

	hall, _, err := svc.Create(context.Background(), principal, reqCtx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if hall.Name == nil || *hall.Name != "Hall B" {
		t.Errorf("expected name='Hall B', got %v", hall.Name)
	}
}

// Test 10: Developer forbidden to create hall
func TestHallService_Create_DeveloperForbidden(t *testing.T) {
	repo := &fakeHallRepo{}
	enforcer := &fakeHallLegacyRules{
		createDecision: Decision{Allow: false, Reason: "developer not allowed"},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	principal := Principal{TenantID: "t1", UserID: "u-dev", Role: "developer"}
	reqCtx := RequestContext{}
	input := HallCreateInput{Name: "Hall C", OwnerUserID: "u-dev", CurrentFilmID: "film-3"}

	_, _, err := svc.Create(context.Background(), principal, reqCtx, input)
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// Test 11: Evaluate error propagates
func TestHallService_Create_EvaluateError(t *testing.T) {
	repo := &fakeHallRepo{}
	evalErr := errors.New("pdp failure")
	enforcer := &fakeHallLegacyRules{createErr: evalErr}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	input := HallCreateInput{Name: "Hall X", OwnerUserID: "u1", CurrentFilmID: "f1"}
	_, _, err := svc.Create(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, input)
	if !errors.Is(err, evalErr) {
		t.Errorf("expected evaluate error, got %v", err)
	}
}

// Test 12: Repository create error propagates
func TestHallService_Create_RepoError(t *testing.T) {
	repoErr := errors.New("db write failed")
	repo := &fakeHallRepo{createErr: repoErr}
	enforcer := &fakeHallLegacyRules{
		createDecision: Decision{Allow: true},
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	input := HallCreateInput{Name: "Hall Y", OwnerUserID: "u1", CurrentFilmID: "f1"}
	_, _, err := svc.Create(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, input)
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repository error, got %v", err)
	}
}

// Test 13: Read enforcement error after create propagates
func TestHallService_Create_ReadEnforcementError(t *testing.T) {
	repo := &fakeHallRepo{}
	readErr := errors.New("read enforcement failed")
	enforcer := &fakeHallLegacyRules{
		createDecision: Decision{Allow: true},
		readErr:        readErr,
	}
	svc := newHallServiceFromLegacyRules(repo, enforcer, nil, nil, nil)

	input := HallCreateInput{Name: "Hall Z", OwnerUserID: "u1", CurrentFilmID: "f1"}
	_, _, err := svc.Create(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, input)
	if !errors.Is(err, readErr) {
		t.Errorf("expected read enforcement error, got %v", err)
	}
}

func TestHallService_Create_SecureRepoWritesAudit_Allow(t *testing.T) {
	secureRepo := &fakeSecureHallRepo{
		createCandidate: HallReadCandidate{
			Record:         HallRecord{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-agent", CurrentFilmID: "film-1"},
			Resource:       Resource{Type: "hall", ID: "hall-1", TenantID: "t1"},
			SpectatorCount: 0,
		},
		applyView: HallReadView{
			Output: HallOutput{
				ID:            "hall-1",
				Name:          stringPtr("Hall A"),
				OwnerUserID:   "u-ag…",
				CurrentFilmID: "film…",
			},
			FieldsMasked:  []string{"owner_user_id", "current_film_id"},
			DecisionHash:  "hash-hall-create",
			PolicyID:      "cinema-default",
			PolicyVersion: "v1",
		},
	}
	authorizer := &hallAuthorizerStub{
		decisions: map[Action]Decision{
			ActionHallCreate: {Allow: true, Hash: "hash-hall-write", PolicyID: "cinema-default", PolicyVersion: "v1", Reason: "write_allowed"},
			ActionHallRead:   {Allow: true, Hash: "hash-hall-create", PolicyID: "cinema-default", PolicyVersion: "v1", Reason: "read_allowed"},
		},
	}
	mockWriter := &mockAuditService{}
	svc := NewHallServiceWithSecureRepo(
		secureRepo,
		authorizer,
		nil,
		NewAuditService(&mockAuditRepositoryAdapter{mock: mockWriter}, nil, slog.Default()),
		nil,
		nil,
	)

	principal := Principal{TenantID: "t1", UserID: "u-agent", Role: "agent"}
	reqCtx := RequestContext{RequestID: "req-hall-create-allow"}
	input := HallCreateInput{Name: "Hall A", OwnerUserID: "u-agent", CurrentFilmID: "film-1"}

	_, _, err := svc.Create(context.Background(), principal, reqCtx, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if mockWriter.writeCalls != 1 {
		t.Fatalf("expected 1 audit write, got %d", mockWriter.writeCalls)
	}
	if mockWriter.lastAuditLog.Action != "hall.create" {
		t.Fatalf("expected hall.create audit, got %q", mockWriter.lastAuditLog.Action)
	}
	if mockWriter.lastAuditLog.Outcome != "allow" {
		t.Fatalf("expected allow outcome, got %q", mockWriter.lastAuditLog.Outcome)
	}
	if mockWriter.lastAuditLog.PolicyID != "cinema-default" || mockWriter.lastAuditLog.PolicyVersion != "v1" {
		t.Fatalf("expected policy metadata in audit, got %q/%q", mockWriter.lastAuditLog.PolicyID, mockWriter.lastAuditLog.PolicyVersion)
	}
	if mockWriter.lastAuditLog.ResourceID == "" {
		t.Fatalf("expected resource id to be populated")
	}
}

func TestHallService_Create_WritesAudit_Deny(t *testing.T) {
	repo := &fakeHallRepo{}
	enforcer := &fakeHallLegacyRules{
		createDecision: Decision{
			Allow:         false,
			Reason:        "write_forbidden",
			Hash:          "hash-deny",
			PolicyID:      "cinema-default",
			PolicyVersion: "v1",
		},
	}
	mockWriter := &mockAuditService{}
	svc := newHallServiceFromLegacyRules(
		repo,
		enforcer,
		NewAuditService(&mockAuditRepositoryAdapter{mock: mockWriter}, nil, slog.Default()),
		nil,
		nil,
	)

	_, _, err := svc.Create(context.Background(), Principal{TenantID: "t1", UserID: "u-dev", Role: "developer"}, RequestContext{RequestID: "req-hall-deny"}, HallCreateInput{
		Name: "Hall C", OwnerUserID: "u-dev", CurrentFilmID: "film-3",
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if mockWriter.writeCalls != 1 {
		t.Fatalf("expected 1 audit write, got %d", mockWriter.writeCalls)
	}
	if mockWriter.lastAuditLog.Action != "hall.create" || mockWriter.lastAuditLog.Outcome != "deny" {
		t.Fatalf("expected deny hall.create audit, got action=%q outcome=%q", mockWriter.lastAuditLog.Action, mockWriter.lastAuditLog.Outcome)
	}
	if mockWriter.lastAuditLog.DecisionHash != "hash-deny" {
		t.Fatalf("expected decision hash to be propagated, got %q", mockWriter.lastAuditLog.DecisionHash)
	}
}

func TestHallService_List_SecureRepoWritesAudit_Allow(t *testing.T) {
	secureRepo := &fakeSecureHallRepo{
		listCandidates: []HallReadCandidate{
			{
				Record:         HallRecord{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-owner", CurrentFilmID: "film-1"},
				Resource:       Resource{Type: "hall", ID: "hall-1", TenantID: "t1"},
				SpectatorCount: 0,
			},
		},
		applyView: HallReadView{
			Output: HallOutput{
				ID:            "hall-1",
				Name:          stringPtr("Hall A"),
				OwnerUserID:   "u-ow…",
				CurrentFilmID: "film…",
			},
			FieldsMasked:  []string{"owner_user_id", "current_film_id"},
			DecisionHash:  "hash-hall-read",
			PolicyID:      "cinema-default",
			PolicyVersion: "v1",
		},
	}
	authorizer := &hallAuthorizerStub{
		decisions: map[Action]Decision{
			ActionHallRead: {Allow: true, Hash: "hash-hall-read", PolicyID: "cinema-default", PolicyVersion: "v1", Reason: "read_allowed"},
		},
	}
	mockWriter := &mockAuditService{}
	svc := &hallService{
		secureRepo: secureRepo,
		authorizer: authorizer,
		audit:      NewAuditService(&mockAuditRepositoryAdapter{mock: mockWriter}, nil, slog.Default()),
	}

	_, _, err := svc.List(context.Background(), Principal{TenantID: "t1", UserID: "u-admin", Role: "admin"}, RequestContext{RequestID: "req-hall-read"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if mockWriter.writeCalls != 1 {
		t.Fatalf("expected 1 audit write, got %d", mockWriter.writeCalls)
	}
	if mockWriter.lastAuditLog.Action != "hall.read" || mockWriter.lastAuditLog.Outcome != "allow" {
		t.Fatalf("expected allow hall.read audit, got action=%q outcome=%q", mockWriter.lastAuditLog.Action, mockWriter.lastAuditLog.Outcome)
	}
	if !contains(mockWriter.lastAuditLog.FieldsMasked, "owner_user_id") {
		t.Fatalf("expected masked fields in audit, got %v", mockWriter.lastAuditLog.FieldsMasked)
	}
}

// ==================== MOCKS ====================

type fakeHallRepo struct {
	halls           []HallRecord
	listErr         error
	createErr       error
	spectatorCounts map[string]int
}

func (f *fakeHallRepo) ListByTenant(_ context.Context, tenantID string) ([]HallRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var result []HallRecord
	for _, h := range f.halls {
		if h.TenantID == tenantID {
			result = append(result, h)
		}
	}
	return result, nil
}

func (f *fakeHallRepo) Create(_ context.Context, hall *domain.Hall) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.halls = append(f.halls, HallRecord{
		TenantID:      hall.TenantID,
		ID:            hall.ID,
		Name:          hall.Name,
		OwnerUserID:   hall.OwnerUserID,
		CurrentFilmID: hall.CurrentFilmID,
	})
	return nil
}

func (f *fakeHallRepo) CountSpectators(_ context.Context, tenantID, hallID string) (int, error) {
	if f.spectatorCounts == nil {
		return 0, nil
	}
	return f.spectatorCounts[hallID], nil
}

func (f *fakeHallRepo) FindByID(_ context.Context, tenantID string, hallID string) (*domain.Hall, error) {
	for _, h := range f.halls {
		if h.TenantID == tenantID && h.ID == hallID {
			return &domain.Hall{
				TenantID:      h.TenantID,
				ID:            h.ID,
				Name:          h.Name,
				OwnerUserID:   h.OwnerUserID,
				CurrentFilmID: h.CurrentFilmID,
			}, nil
		}
	}
	return nil, nil
}

type fakeSecureHallRepo struct {
	listCandidates  []HallReadCandidate
	listErr         error
	createCandidate HallReadCandidate
	createErr       error
	applyView       HallReadView
	applyErr        error
}

func (f *fakeSecureHallRepo) ListCandidates(_ context.Context, _ string) ([]HallReadCandidate, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listCandidates, nil
}

func (f *fakeSecureHallRepo) Create(_ context.Context, _ string, _ HallCreateInput, _ Decision) (HallReadCandidate, error) {
	if f.createErr != nil {
		return HallReadCandidate{}, f.createErr
	}
	return f.createCandidate, nil
}

func (f *fakeSecureHallRepo) ApplyReadDecision(_ context.Context, _ HallReadCandidate, _ Decision) (HallReadView, error) {
	if f.applyErr != nil {
		return HallReadView{}, f.applyErr
	}
	return f.applyView, nil
}

type hallAuthorizerStub struct {
	decisions map[Action]Decision
	err       error
}

func (a *hallAuthorizerStub) Authorize(_ context.Context, input PolicyInput) (Decision, error) {
	if a.err != nil {
		return Decision{}, a.err
	}
	if decision, ok := a.decisions[input.Access.Action]; ok {
		return decision, nil
	}
	return Decision{}, nil
}

type mockAuditRepositoryAdapter struct {
	mock *mockAuditService
}

func (m *mockAuditRepositoryAdapter) Create(ctx context.Context, log *domain.AuditLog) error {
	if m == nil || m.mock == nil {
		return nil
	}
	return m.mock.WriteAudit(ctx, log)
}

func (m *mockAuditRepositoryAdapter) List(_ context.Context, _ string, _ int) ([]*domain.AuditLog, error) {
	return nil, errors.New("not implemented")
}

type fakeHallLegacyRules struct {
	createDecision Decision
	createErr      error
	readResult     HallReadResult
	readErr        error
}

func newHallServiceFromLegacyRules(repo *fakeHallRepo, rules *fakeHallLegacyRules, audit *AuditService, perf PerfWriter, runtime RuntimeSettings) HallService {
	return NewHallServiceWithSecureRepo(
		&legacyHallSecureRepoForTest{raw: repo, rules: rules},
		&legacyHallAuthorizerForTest{rules: rules},
		nil,
		audit,
		perf,
		runtime,
	)
}

type legacyHallSecureRepoForTest struct {
	raw      *fakeHallRepo
	rules    *fakeHallLegacyRules
}

func (r *legacyHallSecureRepoForTest) ListCandidates(_ context.Context, _ string) ([]HallReadCandidate, error) {
	if r.raw.listErr != nil {
		return nil, r.raw.listErr
	}
	candidates := make([]HallReadCandidate, 0, len(r.raw.halls))
	for _, record := range r.raw.halls {
		resource, err := BuildHallReadResource(context.Background(), nil, record)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, HallReadCandidate{
			Record:         record,
			Resource:       resource,
			SpectatorCount: r.raw.spectatorCounts[record.ID],
		})
	}
	return candidates, nil
}

func (r *legacyHallSecureRepoForTest) Create(_ context.Context, tenantID string, input HallCreateInput, decision Decision) (HallReadCandidate, error) {
	if !decision.Allow {
		return HallReadCandidate{}, ErrForbidden
	}
	if r.raw.createErr != nil {
		return HallReadCandidate{}, r.raw.createErr
	}
	record := HallRecord{
		TenantID:      tenantID,
		ID:            "test-hall-id",
		Name:          input.Name,
		OwnerUserID:   input.OwnerUserID,
		CurrentFilmID: input.CurrentFilmID,
	}
	resource, err := BuildHallReadResource(context.Background(), nil, record)
	if err != nil {
		return HallReadCandidate{}, err
	}
	return HallReadCandidate{Record: record, Resource: resource}, nil
}

func (r *legacyHallSecureRepoForTest) ApplyReadDecision(_ context.Context, candidate HallReadCandidate, decision Decision) (HallReadView, error) {
	if !decision.Allow {
		return HallReadView{}, ErrForbidden
	}
	if r.rules.readErr != nil {
		return HallReadView{}, r.rules.readErr
	}
	result := r.rules.readResult
	return HallReadView{
		Output: HallOutput{
			ID:             candidate.Record.ID,
			Name:           result.Name,
			OwnerUserID:    result.OwnerUserID,
			CurrentFilmID:  result.CurrentFilmID,
			SpectatorCount: candidate.SpectatorCount,
		},
		DecisionHash:  result.DecisionHash,
		PolicyID:      result.PolicyID,
		PolicyVersion: result.PolicyVersion,
		FieldsMasked:  result.FieldsMasked,
		FieldsDenied:  result.FieldsDenied,
	}, nil
}

type legacyHallAuthorizerForTest struct {
	rules *fakeHallLegacyRules
}

func (a *legacyHallAuthorizerForTest) Authorize(_ context.Context, input PolicyInput) (Decision, error) {
	switch input.Access.Action {
	case ActionHallCreate:
		if a.rules.createErr != nil {
			return Decision{}, a.rules.createErr
		}
		return a.rules.createDecision, nil
	case ActionHallRead:
		return Decision{Allow: true}, nil
	default:
		return Decision{}, nil
	}
}

// Helper
func stringPtr(s string) *string {
	return &s
}
