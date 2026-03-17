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
	enforcer := &fakeHallEnforcer{
		readResult: HallReadResult{
			Name:          stringPtr("Hall A"),
			OwnerUserID:   "u-admin",
			CurrentFilmID: "film-1",
			FieldsMasked:  []string{},
			FieldsDenied:  []string{},
		},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		readResult: HallReadResult{
			Name:          stringPtr("Hall A"),
			OwnerUserID:   "u-ow…", // Masked
			CurrentFilmID: "film…", // Masked
			FieldsMasked:  []string{"owner_user_id", "current_film_id"},
			FieldsDenied:  []string{},
		},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		readResult: HallReadResult{
			Name:          stringPtr("Hall A"),
			OwnerUserID:   "u-owner",
			CurrentFilmID: "film-1",
			FieldsMasked:  []string{},
			FieldsDenied:  []string{},
		},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	svc := NewHallService(repo, nil, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{readErr: enforcerErr}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		readResult: HallReadResult{Name: stringPtr("Hall A"), OwnerUserID: "u1", CurrentFilmID: "f1"},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		createDecision: AuthorizationDecision{Allow: true, Reason: "admin write"},
		readResult:     HallReadResult{Name: stringPtr("Hall A"), OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		createDecision: AuthorizationDecision{Allow: true, Reason: "agent write"},
		readResult:     HallReadResult{Name: stringPtr("Hall B"), OwnerUserID: "u-agent", CurrentFilmID: "film-2"},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		createDecision: AuthorizationDecision{Allow: false, Reason: "developer not allowed"},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{createErr: evalErr}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		createDecision: AuthorizationDecision{Allow: true},
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

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
	enforcer := &fakeHallEnforcer{
		createDecision: AuthorizationDecision{Allow: true},
		readErr:        readErr,
	}
	svc := NewHallService(repo, enforcer, nil, nil, nil)

	input := HallCreateInput{Name: "Hall Z", OwnerUserID: "u1", CurrentFilmID: "f1"}
	_, _, err := svc.Create(context.Background(), Principal{TenantID: "t1", Role: "admin"}, RequestContext{}, input)
	if !errors.Is(err, readErr) {
		t.Errorf("expected read enforcement error, got %v", err)
	}
}

func TestHallService_Create_SecureRepoWritesAudit_Allow(t *testing.T) {
	rawRepo := &fakeHallRepo{}
	secureRepo := &fakeSecureHallRepo{
		createView: HallReadView{
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
	enforcer := &fakeHallEnforcer{
		createDecision: AuthorizationDecision{Allow: true, Reason: "write_allowed"},
	}
	mockWriter := &mockAuditService{}
	svc := NewHallServiceWithSecureRepo(
		rawRepo,
		secureRepo,
		enforcer,
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
	enforcer := &fakeHallEnforcer{
		createDecision: AuthorizationDecision{
			Allow:         false,
			Reason:        "write_forbidden",
			DecisionHash:  "hash-deny",
			PolicyID:      "cinema-default",
			PolicyVersion: "v1",
		},
	}
	mockWriter := &mockAuditService{}
	svc := &hallService{
		repo:     repo,
		enforcer: enforcer,
		audit:    NewAuditService(&mockAuditRepositoryAdapter{mock: mockWriter}, nil, slog.Default()),
	}

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
	rawRepo := &fakeHallRepo{}
	secureRepo := &fakeSecureHallRepo{
		listViews: []HallReadView{
			{
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
		},
	}
	mockWriter := &mockAuditService{}
	svc := &hallService{
		repo:       rawRepo,
		secureRepo: secureRepo,
		enforcer:   &fakeHallEnforcer{},
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
	listViews  []HallReadView
	listErr    error
	createView HallReadView
	createErr  error
}

func (f *fakeSecureHallRepo) ListByTenant(_ context.Context, _ string) ([]HallReadView, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listViews, nil
}

func (f *fakeSecureHallRepo) Create(_ context.Context, _ *domain.Hall) (HallReadView, error) {
	if f.createErr != nil {
		return HallReadView{}, f.createErr
	}
	return f.createView, nil
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

type fakeHallEnforcer struct {
	createDecision AuthorizationDecision
	createErr      error
	readResult     HallReadResult
	readErr        error
}

func (f *fakeHallEnforcer) EvaluateHallCreate(_ context.Context, _ Principal, _ RequestContext, _ string) (AuthorizationDecision, error) {
	return f.createDecision, f.createErr
}

func (f *fakeHallEnforcer) EvaluateHallRead(_ context.Context, _ Principal, _ RequestContext, _ string, _ string) (AuthorizationDecision, error) {
	return AuthorizationDecision{Allow: true}, nil
}

func (f *fakeHallEnforcer) EnforceHallRead(_ context.Context, _ Principal, _ RequestContext, _ HallReadInput) (HallReadResult, error) {
	return f.readResult, f.readErr
}

// Stub implementations for film methods (not used in hall tests)
func (f *fakeHallEnforcer) EvaluateAuditRead(_ context.Context, _ Principal, _ RequestContext) (AuthorizationDecision, error) {
	return AuthorizationDecision{}, errors.New("not implemented")
}

func (f *fakeHallEnforcer) EvaluatePerfRead(_ context.Context, _ Principal, _ RequestContext) (AuthorizationDecision, error) {
	return AuthorizationDecision{}, errors.New("not implemented")
}

func (f *fakeHallEnforcer) EvaluateFilmCreate(_ context.Context, _ Principal, _ RequestContext) (AuthorizationDecision, error) {
	return AuthorizationDecision{}, errors.New("not implemented")
}

func (f *fakeHallEnforcer) EvaluateFilmUpdateTime(_ context.Context, _ Principal, _ RequestContext, _ string) (AuthorizationDecision, error) {
	return AuthorizationDecision{}, errors.New("not implemented")
}

func (f *fakeHallEnforcer) EnforceFilmRead(_ context.Context, _ Principal, _ RequestContext, _ FilmReadInput) (FilmReadResult, error) {
	return FilmReadResult{}, errors.New("not implemented")
}

// Spectator policy stubs (not used in hall tests)
func (f *fakeHallEnforcer) EvaluateSpectatorCreate(_ context.Context, _ Principal, _ RequestContext, _ string) (AuthorizationDecision, error) {
	return AuthorizationDecision{}, errors.New("not implemented")
}

func (f *fakeHallEnforcer) EvaluateSpectatorSearch(_ context.Context, _ Principal, _ RequestContext) (AuthorizationDecision, error) {
	return AuthorizationDecision{}, errors.New("not implemented")
}

func (f *fakeHallEnforcer) EnforceSpectatorRead(_ context.Context, _ Principal, _ RequestContext, _ SpectatorReadInput) (SpectatorReadResult, error) {
	return SpectatorReadResult{}, errors.New("not implemented")
}

// Crypto delegation stubs
func (f *fakeHallEnforcer) Encrypt(_ context.Context, plaintext string) (string, error) {
	return "encrypted-" + plaintext, nil
}

func (f *fakeHallEnforcer) Decrypt(_ context.Context, ciphertext string) (string, error) {
	return "decrypted", nil
}

func (f *fakeHallEnforcer) GetPepper(_ context.Context, path string) ([]byte, error) {
	return []byte("test-pepper"), nil
}

// Enforce create stubs
func (f *fakeHallEnforcer) EnforceFilmCreate(_ context.Context, _ Principal, _ RequestContext, _ FilmCreatePlain) (FilmCreateEncrypted, error) {
	return FilmCreateEncrypted{}, errors.New("not implemented")
}

func (f *fakeHallEnforcer) EnforceSpectatorCreate(_ context.Context, _ Principal, _ RequestContext, _ SpectatorCreatePlain) (SpectatorCreateEncrypted, error) {
	return SpectatorCreateEncrypted{}, errors.New("not implemented")
}

// Helper
func stringPtr(s string) *string {
	return &s
}
