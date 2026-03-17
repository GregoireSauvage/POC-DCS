package service

import (
	"context"
	"errors"
	"testing"
)

func TestFilmService_Create_AuthorizesWriteThenReadAndDelegatesToRepo(t *testing.T) {
	candidate := FilmReadCandidate{
		Record:   FilmRecord{TenantID: "t1", ID: "film-1", Title: "Matrix", TimeElapsedCT: "vault:v1:encrypted"},
		Resource: Resource{Type: "film", ID: "film-1", TenantID: "t1"},
	}
	repo := &filmRepoStub{
		createCandidate: candidate,
		applyViews: map[string]FilmReadView{
			"film-1": {
				Output:          FilmOutput{ID: "film-1", Title: "Matrix", TimeElapsed: 136},
				FieldsDecrypted: []string{"time_elapsed"},
				DecisionHash:    "read-hash",
				PolicyID:        "cinema-default",
				PolicyVersion:   "v1",
			},
		},
	}
	authorizer := &filmAuthorizerStub{decisions: []Decision{allowDecision("write_allowed", "write-hash"), allowDecision("read_allowed", "read-hash")}}
	audit := &filmAuditCapture{}
	perf := &filmPerfCapture{}
	svc := NewFilmService(repo, authorizer, nil, audit, perf, filmRuntimeSettings{dcsEnabled: true, cacheLevel: 2})

	out, _, err := svc.Create(context.Background(), filmPrincipal("admin"), filmRequest("req-create"), FilmCreateInput{Title: "Matrix", TimeElapsed: 136})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if out.TimeElapsed != 136 {
		t.Fatalf("expected decrypted time_elapsed, got %v", out.TimeElapsed)
	}
	if repo.createCalls != 1 || repo.applyCalls != 1 {
		t.Fatalf("unexpected repo call counts: create=%d apply=%d", repo.createCalls, repo.applyCalls)
	}
	if repo.lastCreateInput.Title != "Matrix" || repo.lastCreateInput.TimeElapsed != 136 {
		t.Fatalf("unexpected create input: %+v", repo.lastCreateInput)
	}
	if repo.lastCreateDecision.Hash != "write-hash" {
		t.Fatalf("expected write decision hash to reach repo, got %q", repo.lastCreateDecision.Hash)
	}
	if len(authorizer.calls) != 2 || authorizer.calls[0].Access.Action != ActionFilmCreate || authorizer.calls[1].Access.Action != ActionFilmRead {
		t.Fatalf("unexpected authorize sequence: %+v", authorizer.calls)
	}
	if audit.calls != 1 || audit.last == nil || audit.last.Action != "film.create" || audit.last.Outcome != "allow" {
		t.Fatalf("unexpected audit log: %+v", audit.last)
	}
	if perf.calls != 1 {
		t.Fatalf("expected 1 perf write, got %d", perf.calls)
	}
}

func TestFilmService_Create_DenyDoesNotCallRepository(t *testing.T) {
	repo := &filmRepoStub{}
	authorizer := &filmAuthorizerStub{decisions: []Decision{denyDecision("write_forbidden", "write-deny")}}
	audit := &filmAuditCapture{}
	perf := &filmPerfCapture{}
	svc := NewFilmService(repo, authorizer, nil, audit, perf, filmRuntimeSettings{dcsEnabled: true, cacheLevel: 2})

	_, _, err := svc.Create(context.Background(), filmPrincipal("developer"), filmRequest("req-deny"), FilmCreateInput{Title: "Matrix", TimeElapsed: 136})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if repo.createCalls != 0 || repo.applyCalls != 0 {
		t.Fatalf("repository should not be called on write deny, got create=%d apply=%d", repo.createCalls, repo.applyCalls)
	}
	if audit.calls != 1 || audit.last == nil || audit.last.Outcome != "deny" {
		t.Fatalf("unexpected deny audit: %+v", audit.last)
	}
	if perf.calls != 1 {
		t.Fatalf("expected 1 perf write, got %d", perf.calls)
	}
}
