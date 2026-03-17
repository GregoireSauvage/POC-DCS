package service

import (
	"context"
	"errors"
	"testing"
)

func TestFilmService_UpdateTime_AllowWritesAudit(t *testing.T) {
	candidate := FilmReadCandidate{
		Record:   FilmRecord{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: "vault:v1:updated"},
		Resource: Resource{Type: "film", ID: "film-1", TenantID: "t1"},
	}
	repo := &filmRepoStub{
		updateCandidate: candidate,
		applyViews: map[string]FilmReadView{
			"film-1": {
				Output:          FilmOutput{ID: "film-1", Title: "Interstellar", TimeElapsed: 150},
				FieldsDecrypted: []string{"time_elapsed"},
				DecisionHash:    "read-after-update",
				PolicyID:        "cinema-default",
				PolicyVersion:   "v1",
			},
		},
	}
	authorizer := &filmAuthorizerStub{decisions: []Decision{allowDecision("write_allowed", "write-update"), allowDecision("read_allowed", "read-after-update")}}
	audit := &filmAuditCapture{}
	svc := NewFilmService(repo, authorizer, nil, audit, nil, nil)

	_, _, err := svc.UpdateTime(context.Background(), filmPrincipal("admin"), filmRequest("req-update"), "film-1", 150)
	if err != nil {
		t.Fatalf("UpdateTime: %v", err)
	}
	if audit.calls != 1 || audit.last == nil {
		t.Fatalf("expected 1 audit log, got %+v", audit.last)
	}
	if audit.last.Action != "film.update_time" || audit.last.Outcome != "allow" {
		t.Fatalf("unexpected audit log: %+v", audit.last)
	}
	if value, ok := audit.last.Details["new_time_elapsed"]; !ok || value != 150 {
		t.Fatalf("expected new_time_elapsed=150, got %+v", audit.last.Details)
	}
}

func TestFilmService_List_DenyWritesAudit(t *testing.T) {
	repo := &filmRepoStub{listCandidates: []FilmReadCandidate{{Record: FilmRecord{TenantID: "t1", ID: "film-1"}, Resource: Resource{Type: "film", ID: "film-1", TenantID: "t1"}}}}
	authorizer := &filmAuthorizerStub{decisions: []Decision{denyDecision("read_forbidden", "read-deny")}}
	audit := &filmAuditCapture{}
	svc := NewFilmService(repo, authorizer, nil, audit, nil, nil)

	_, _, err := svc.List(context.Background(), filmPrincipal("developer"), filmRequest("req-list-deny"))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
	if audit.calls != 1 || audit.last == nil || audit.last.Outcome != "deny" {
		t.Fatalf("unexpected deny audit: %+v", audit.last)
	}
	if audit.last.DecisionHash != "read-deny" {
		t.Fatalf("expected decision hash read-deny, got %q", audit.last.DecisionHash)
	}
}
