package service

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type mockPerfLogRepository struct {
	createCalls       int
	createErr         error
	lastCreated       *domain.PerfLog
	listLogs          []*domain.PerfLog
	listErr           error
	listCalls         int
	lastTenantID      string
	lastLimit         int
	lastAction        *string
	lastSource        *string
	summaryRows       []*domain.PerfSummary
	summaryErr        error
	summaryCalls      int
	lastSummaryAction *string
	lastCacheLevel    *int
	lastAllCache      bool
}

type mockPerfAuthorizer struct {
	decision      Decision
	err           error
	authorizeCalls int
	lastPrincipal *Principal
	lastReqCtx    *RequestContext
}

func (m *mockPerfAuthorizer) Authorize(ctx context.Context, input PolicyInput) (Decision, error) {
	principal := input.Access.Principal
	reqCtx := input.Access.Request
	m.authorizeCalls++
	m.lastPrincipal = &principal
	m.lastReqCtx = &reqCtx
	if m.err != nil {
		return Decision{}, m.err
	}
	return m.decision, nil
}

func (m *mockPerfLogRepository) Create(ctx context.Context, log *domain.PerfLog) error {
	_ = ctx
	m.createCalls++
	m.lastCreated = log
	return m.createErr
}

func (m *mockPerfLogRepository) List(
	ctx context.Context,
	tenantID string,
	limit int,
	action *string,
	source *string,
) ([]*domain.PerfLog, error) {
	_ = ctx
	m.listCalls++
	m.lastTenantID = tenantID
	m.lastLimit = limit
	m.lastAction = action
	m.lastSource = source
	return m.listLogs, m.listErr
}

func (m *mockPerfLogRepository) Summary(
	ctx context.Context,
	tenantID string,
	action *string,
	cacheLevel *int,
	allCacheLevels bool,
	source *string,
) ([]*domain.PerfSummary, error) {
	_ = ctx
	m.summaryCalls++
	m.lastTenantID = tenantID
	m.lastSummaryAction = action
	m.lastCacheLevel = cacheLevel
	m.lastAllCache = allCacheLevels
	m.lastSource = source
	return m.summaryRows, m.summaryErr
}

func TestPerfService_List_Admin(t *testing.T) {
	action := "film.read"
	repo := &mockPerfLogRepository{
		listLogs: []*domain.PerfLog{{Action: "film.read"}},
	}
	// Use enforcer that allows access (DCS required - no fallback)
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: true},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-1"}

	logs, err := svc.List(context.Background(), principal, reqCtx, 50, &action, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(logs) != 1 || logs[0].Action != "film.read" {
		t.Fatalf("expected one film.read log")
	}
	if repo.listCalls != 1 {
		t.Fatalf("expected repo list called once, got %d", repo.listCalls)
	}
	if repo.lastTenantID != "t1" {
		t.Fatalf("expected tenant t1, got %q", repo.lastTenantID)
	}
	if repo.lastLimit != 50 {
		t.Fatalf("expected limit 50, got %d", repo.lastLimit)
	}
	if repo.lastAction == nil || *repo.lastAction != "film.read" {
		t.Fatalf("expected action filter passed to repo")
	}
	if repo.lastSource == nil || *repo.lastSource != "go" {
		t.Fatalf("expected default source filter passed to repo")
	}
}

func TestPerfService_Write_CallsRepo(t *testing.T) {
	repo := &mockPerfLogRepository{}
	svc := NewPerfService(repo, nil, "go")

	log := &domain.PerfLog{
		TenantID:  "t1",
		Action:    "film.read",
		RequestID: "req-1",
	}

	err := svc.Write(context.Background(), log)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.createCalls != 1 {
		t.Fatalf("expected create called once, got %d", repo.createCalls)
	}
	if repo.lastCreated != log {
		t.Fatalf("expected log passed to repo")
	}
	if log.Source != "go" {
		t.Fatalf("expected source to be defaulted, got %q", log.Source)
	}
}

func TestPerfService_Write_RepoError(t *testing.T) {
	repo := &mockPerfLogRepository{createErr: errors.New("db error")}
	svc := NewPerfService(repo, nil, "go")

	err := svc.Write(context.Background(), &domain.PerfLog{TenantID: "t1"})
	if err == nil {
		t.Fatal("expected repo error")
	}
}

func TestPerfService_List_NonAdmin(t *testing.T) {
	repo := &mockPerfLogRepository{}
	// Use enforcer that denies access (simulates PDP denying non-admin)
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: false},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "developer"}
	reqCtx := RequestContext{}

	_, err := svc.List(context.Background(), principal, reqCtx, 50, nil, nil)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if repo.listCalls != 0 {
		t.Fatalf("expected repo not called for non-admin")
	}
}

func TestPerfService_List_RepoError(t *testing.T) {
	repo := &mockPerfLogRepository{listErr: errors.New("db error")}
	// Use enforcer that allows (we want to test repo error, not enforcer denial)
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: true},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	_, err := svc.List(context.Background(), principal, reqCtx, 50, nil, nil)
	if err == nil {
		t.Fatal("expected repo error")
	}
	if errors.Is(err, ErrForbidden) {
		t.Fatalf("expected repo error, got ErrForbidden")
	}
}

func TestPerfService_Summary_Admin(t *testing.T) {
	action := "film.read"
	cacheLevel := 2
	repo := &mockPerfLogRepository{
		summaryRows: []*domain.PerfSummary{{Action: "film.read"}},
	}
	// Use enforcer that allows access (DCS required - no fallback)
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: true},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	rows, err := svc.Summary(context.Background(), principal, reqCtx, &action, &cacheLevel, false, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(rows) != 1 || rows[0].Action != "film.read" {
		t.Fatalf("expected one summary row")
	}
	if repo.summaryCalls != 1 {
		t.Fatalf("expected repo summary called once, got %d", repo.summaryCalls)
	}
	if repo.lastTenantID != "t1" {
		t.Fatalf("expected tenant t1, got %q", repo.lastTenantID)
	}
	if repo.lastSummaryAction == nil || *repo.lastSummaryAction != "film.read" {
		t.Fatalf("expected action filter passed to repo")
	}
	if repo.lastCacheLevel == nil || *repo.lastCacheLevel != 2 {
		t.Fatalf("expected cache_level 2, got %v", repo.lastCacheLevel)
	}
	if repo.lastAllCache {
		t.Fatalf("expected all_cache_levels false")
	}
}

func TestPerfService_Summary_NonAdmin(t *testing.T) {
	repo := &mockPerfLogRepository{}
	// Use enforcer that denies access (simulates PDP denying non-admin)
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: false},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "agent"}
	reqCtx := RequestContext{}

	_, err := svc.Summary(context.Background(), principal, reqCtx, nil, nil, false, nil)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if repo.summaryCalls != 0 {
		t.Fatalf("expected repo not called for non-admin")
	}
}

func TestPerfService_Summary_RepoError(t *testing.T) {
	repo := &mockPerfLogRepository{summaryErr: errors.New("db error")}
	// Use enforcer that allows (we want to test repo error, not enforcer denial)
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: true},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	_, err := svc.Summary(context.Background(), principal, reqCtx, nil, nil, true, nil)
	if err == nil {
		t.Fatal("expected repo error")
	}
	if errors.Is(err, ErrForbidden) {
		t.Fatalf("expected repo error, got ErrForbidden")
	}
}

func TestPerfService_List_EnforcerAllows(t *testing.T) {
	repo := &mockPerfLogRepository{
		listLogs: []*domain.PerfLog{{Action: "film.read"}},
	}
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: true},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-1"}

	logs, err := svc.List(context.Background(), principal, reqCtx, 50, nil, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if enforcer.authorizeCalls != 1 {
		t.Fatalf("expected enforcer called once, got %d", enforcer.authorizeCalls)
	}
	if repo.listCalls != 1 {
		t.Fatalf("expected repo called once (enforcer allowed), got %d", repo.listCalls)
	}
}

func TestPerfService_List_EnforcerDenies(t *testing.T) {
	repo := &mockPerfLogRepository{
		listLogs: []*domain.PerfLog{{Action: "film.read"}},
	}
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: false},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-1"}

	_, err := svc.List(context.Background(), principal, reqCtx, 50, nil, nil)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden when enforcer denies, got %v", err)
	}
	if enforcer.authorizeCalls != 1 {
		t.Fatalf("expected enforcer called once, got %d", enforcer.authorizeCalls)
	}
	if repo.listCalls != 0 {
		t.Fatalf("expected repo NOT called when enforcer denies, got %d calls", repo.listCalls)
	}
}

func TestPerfService_List_EnforcerError(t *testing.T) {
	repo := &mockPerfLogRepository{}
	enforcer := &mockPerfAuthorizer{
		err: errors.New("pdp unavailable"),
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	_, err := svc.List(context.Background(), principal, reqCtx, 50, nil, nil)
	if err == nil {
		t.Fatal("expected error from enforcer")
	}
	if errors.Is(err, ErrForbidden) {
		t.Fatalf("expected propagated enforcer error, got ErrForbidden")
	}
	if repo.listCalls != 0 {
		t.Fatalf("expected repo NOT called on enforcer error, got %d calls", repo.listCalls)
	}
}

func TestPerfService_List_EnforcerNil_AdminFallback(t *testing.T) {
	repo := &mockPerfLogRepository{
		listLogs: []*domain.PerfLog{{Action: "film.read"}},
	}
	svc := NewPerfService(repo, nil, "go") // nil enforcer

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	_, err := svc.List(context.Background(), principal, reqCtx, 50, nil, nil)
	if !errors.Is(err, ErrDCSNotConfigured) {
		t.Fatalf("expected ErrDCSNotConfigured, got %v", err)
	}
	if repo.listCalls != 0 {
		t.Fatalf("expected repo NOT called when DCS not configured, got %d calls", repo.listCalls)
	}
}

func TestPerfService_List_EnforcerNil_NonAdminFallback(t *testing.T) {
	repo := &mockPerfLogRepository{}
	svc := NewPerfService(repo, nil, "go") // nil enforcer

	principal := Principal{TenantID: "t1", Role: "developer"}
	reqCtx := RequestContext{}

	_, err := svc.List(context.Background(), principal, reqCtx, 50, nil, nil)
	if !errors.Is(err, ErrDCSNotConfigured) {
		t.Fatalf("expected ErrDCSNotConfigured, got %v", err)
	}
	if repo.listCalls != 0 {
		t.Fatalf("expected repo NOT called when DCS not configured, got %d calls", repo.listCalls)
	}
}

func TestPerfService_List_EnforcerCalledBeforeRepo(t *testing.T) {
	repo := &mockPerfLogRepository{
		listLogs: []*domain.PerfLog{{Action: "film.read"}},
	}
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: false}, // Deny
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	_, _ = svc.List(context.Background(), principal, reqCtx, 50, nil, nil)

	// Enforcer should be called first
	if enforcer.authorizeCalls != 1 {
		t.Fatalf("expected enforcer called, got %d", enforcer.authorizeCalls)
	}
	// Repo should NOT be called (enforcer denied)
	if repo.listCalls != 0 {
		t.Fatalf("expected repo NOT called after enforcer deny, got %d calls", repo.listCalls)
	}
}

func TestPerfService_Summary_EnforcerAllows(t *testing.T) {
	action := "film.read"
	repo := &mockPerfLogRepository{
		summaryRows: []*domain.PerfSummary{{Action: "film.read"}},
	}
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: true},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	rows, err := svc.Summary(context.Background(), principal, reqCtx, &action, nil, false, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 summary row, got %d", len(rows))
	}
	if enforcer.authorizeCalls != 1 {
		t.Fatalf("expected enforcer called once, got %d", enforcer.authorizeCalls)
	}
	if repo.summaryCalls != 1 {
		t.Fatalf("expected repo summary called once, got %d", repo.summaryCalls)
	}
}

func TestPerfService_Summary_EnforcerDenies(t *testing.T) {
	repo := &mockPerfLogRepository{
		summaryRows: []*domain.PerfSummary{{Action: "film.read"}},
	}
	enforcer := &mockPerfAuthorizer{
		decision: Decision{Allow: false},
	}
	svc := NewPerfService(repo, enforcer, "go")

	principal := Principal{TenantID: "t1", Role: "admin"}
	reqCtx := RequestContext{}

	_, err := svc.Summary(context.Background(), principal, reqCtx, nil, nil, false, nil)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden when enforcer denies, got %v", err)
	}
	if enforcer.authorizeCalls != 1 {
		t.Fatalf("expected enforcer called once, got %d", enforcer.authorizeCalls)
	}
	if repo.summaryCalls != 0 {
		t.Fatalf("expected repo NOT called when enforcer denies, got %d calls", repo.summaryCalls)
	}
}
