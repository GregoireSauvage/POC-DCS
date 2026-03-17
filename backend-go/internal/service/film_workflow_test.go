package service

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type filmRepoStub struct {
	listCandidates  []FilmReadCandidate
	listErr         error
	createCandidate FilmReadCandidate
	createErr       error
	updateCandidate FilmReadCandidate
	updateErr       error
	applyViews      map[string]FilmReadView
	applyErr        error

	listCalls          int
	createCalls        int
	updateCalls        int
	applyCalls         int
	lastListTenant     string
	lastCreateTenant   string
	lastCreateInput    FilmCreateInput
	lastCreateDecision Decision
	lastUpdateTenant   string
	lastUpdateFilmID   string
	lastUpdateValue    int
	lastUpdateDecision Decision
	applyDecisions     []Decision
}

func (s *filmRepoStub) ListCandidates(_ context.Context, tenantID string) ([]FilmReadCandidate, error) {
	s.listCalls++
	s.lastListTenant = tenantID
	if s.listErr != nil {
		return nil, s.listErr
	}
	return append([]FilmReadCandidate(nil), s.listCandidates...), nil
}

func (s *filmRepoStub) Create(_ context.Context, tenantID string, input FilmCreateInput, decision Decision) (FilmReadCandidate, error) {
	s.createCalls++
	s.lastCreateTenant = tenantID
	s.lastCreateInput = input
	s.lastCreateDecision = decision
	if s.createErr != nil {
		return FilmReadCandidate{}, s.createErr
	}
	return s.createCandidate, nil
}

func (s *filmRepoStub) UpdateTime(_ context.Context, tenantID, filmID string, timeElapsed int, decision Decision) (FilmReadCandidate, error) {
	s.updateCalls++
	s.lastUpdateTenant = tenantID
	s.lastUpdateFilmID = filmID
	s.lastUpdateValue = timeElapsed
	s.lastUpdateDecision = decision
	if s.updateErr != nil {
		return FilmReadCandidate{}, s.updateErr
	}
	return s.updateCandidate, nil
}

func (s *filmRepoStub) ApplyReadDecision(_ context.Context, candidate FilmReadCandidate, decision Decision) (FilmReadView, error) {
	s.applyCalls++
	s.applyDecisions = append(s.applyDecisions, decision)
	if s.applyErr != nil {
		return FilmReadView{}, s.applyErr
	}
	if view, ok := s.applyViews[candidate.Record.ID]; ok {
		return view, nil
	}
	return FilmReadView{}, errors.New("missing apply view")
}

type filmAuthorizerStub struct {
	decisions []Decision
	calls     []PolicyInput
	index     int
	err       error
}

func (a *filmAuthorizerStub) Authorize(_ context.Context, input PolicyInput) (Decision, error) {
	a.calls = append(a.calls, input)
	if a.err != nil {
		return Decision{}, a.err
	}
	if len(a.decisions) == 0 {
		return Decision{}, errors.New("no decision configured")
	}
	if a.index >= len(a.decisions) {
		return a.decisions[len(a.decisions)-1], nil
	}
	decision := a.decisions[a.index]
	a.index++
	return decision, nil
}

type filmAuditCapture struct {
	calls int
	last  *domain.AuditLog
	logs  []*domain.AuditLog
}

func (c *filmAuditCapture) WriteAudit(_ context.Context, log *domain.AuditLog) error {
	c.calls++
	c.last = log
	c.logs = append(c.logs, log)
	return nil
}

type filmPerfCapture struct {
	calls int
	last  *domain.PerfLog
}

func (c *filmPerfCapture) Write(_ context.Context, log *domain.PerfLog) error {
	c.calls++
	c.last = log
	return nil
}

type filmRuntimeSettings struct {
	dcsEnabled bool
	cacheLevel int
}

func (s filmRuntimeSettings) DcsEnabled() bool { return s.dcsEnabled }
func (s filmRuntimeSettings) CacheLevel() int  { return s.cacheLevel }

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func filmPrincipal(role string) Principal {
	return Principal{TenantID: "t1", UserID: "u-1", Username: role, Role: role}
}

func filmRequest(requestID string) RequestContext {
	return RequestContext{RequestID: requestID, Channel: "web", Purpose: "access", Env: "test"}
}

func allowDecision(reason string, hash string) Decision {
	return Decision{Allow: true, Reason: reason, Hash: hash, PolicyID: "cinema-default", PolicyVersion: "v1"}
}

func denyDecision(reason string, hash string) Decision {
	return Decision{Allow: false, Reason: reason, Hash: hash, PolicyID: "cinema-default", PolicyVersion: "v1"}
}

func TestFilmService_List_AuthorizesEachCandidateAndAggregatesAuditFields(t *testing.T) {
	repo := &filmRepoStub{
		listCandidates: []FilmReadCandidate{
			{Record: FilmRecord{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: "ct-1"}, Resource: Resource{Type: "film", ID: "film-1", TenantID: "t1"}},
			{Record: FilmRecord{TenantID: "t1", ID: "film-2", Title: "Dune", TimeElapsedCT: "ct-2"}, Resource: Resource{Type: "film", ID: "film-2", TenantID: "t1"}},
		},
		applyViews: map[string]FilmReadView{
			"film-1": {Output: FilmOutput{ID: "film-1", Title: "Interstellar", TimeElapsed: 120}, FieldsDecrypted: []string{"time_elapsed"}, DecisionHash: "read-1", PolicyID: "cinema-default", PolicyVersion: "v1"},
			"film-2": {Output: FilmOutput{ID: "film-2", Title: "Dune", TimeElapsed: "1***"}, FieldsMasked: []string{"time_elapsed"}, DecisionHash: "read-2", PolicyID: "cinema-default", PolicyVersion: "v1"},
		},
	}
	authorizer := &filmAuthorizerStub{decisions: []Decision{allowDecision("read_allowed", "read-1"), allowDecision("read_allowed", "read-2")}}
	audit := &filmAuditCapture{}
	perf := &filmPerfCapture{}
	svc := NewFilmService(repo, authorizer, nil, audit, perf, filmRuntimeSettings{dcsEnabled: true, cacheLevel: 2})

	films, _, err := svc.List(context.Background(), filmPrincipal("admin"), filmRequest("req-list"))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(films) != 2 {
		t.Fatalf("expected 2 films, got %d", len(films))
	}
	if repo.listCalls != 1 || repo.applyCalls != 2 {
		t.Fatalf("unexpected repo call counts: list=%d apply=%d", repo.listCalls, repo.applyCalls)
	}
	if len(authorizer.calls) != 2 {
		t.Fatalf("expected 2 authorize calls, got %d", len(authorizer.calls))
	}
	for _, call := range authorizer.calls {
		if call.Access.Action != ActionFilmRead {
			t.Fatalf("expected film.read action, got %q", call.Access.Action)
		}
	}
	if audit.calls != 1 || audit.last == nil || audit.last.Action != "film.read" || audit.last.Outcome != "allow" {
		t.Fatalf("unexpected audit log: %+v", audit.last)
	}
	if !containsString(audit.last.FieldsDecrypted, "time_elapsed") || !containsString(audit.last.FieldsMasked, "time_elapsed") {
		t.Fatalf("expected aggregated field tracking, got decrypted=%v masked=%v", audit.last.FieldsDecrypted, audit.last.FieldsMasked)
	}
	if perf.calls != 1 {
		t.Fatalf("expected 1 perf write, got %d", perf.calls)
	}
}

func TestFilmService_UpdateTime_MapsNotFound(t *testing.T) {
	repo := &filmRepoStub{updateErr: errors.New("film not found")}
	authorizer := &filmAuthorizerStub{decisions: []Decision{allowDecision("write_allowed", "upd-write")}}
	svc := NewFilmService(repo, authorizer, nil, nil, nil, nil)

	_, _, err := svc.UpdateTime(context.Background(), filmPrincipal("admin"), filmRequest("req-update"), "film-404", 99)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
