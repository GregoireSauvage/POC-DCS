package secured

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestHallRepository_ListCandidates_ReturnsBindingVerifiedCandidates(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), testLogger(), deps)

	candidates, err := repo.ListCandidates(withAccess("admin", service.ActionHallRead), "t1")
	if err != nil {
		t.Fatalf("ListCandidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 hall candidate, got %d", len(candidates))
	}
	if candidates[0].Record.ID != "hall-1" || candidates[0].Resource.ID != "hall-1" {
		t.Fatalf("unexpected candidate: %+v", candidates[0])
	}
}

func TestHallRepository_ListCandidates_DeniesMissingBinding(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	repo := NewHallRepository(memory.NewHallRepository(seed), testLogger(), newTestBindingDeps(t))

	_, err := repo.ListCandidates(withAccess("admin", service.ActionHallRead), "t1")
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing binding, got %v", err)
	}
}

func TestHallRepository_ApplyReadDecision_AdminSeesInternalFields(t *testing.T) {
	repo := NewHallRepository(memory.NewHallRepository(nil), testLogger(), newTestBindingDeps(t))
	candidate := service.HallReadCandidate{
		Record: service.HallRecord{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
		Resource: service.Resource{Type: "hall", ID: "hall-1", TenantID: "t1"},
		SpectatorCount: 3,
	}
	decision := service.Decision{
		Allow: true,
		Reason: "read_allowed",
		Hash: "hall-read-admin",
		PolicyID: "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{},
	}

	view, err := repo.ApplyReadDecision(withAccess("admin", service.ActionHallRead), candidate, decision)
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.OwnerUserID != "u-admin" || view.Output.CurrentFilmID != "film-1" {
		t.Fatalf("expected internal fields visible, got %+v", view.Output)
	}
	if view.Output.SpectatorCount != 3 {
		t.Fatalf("expected spectator_count=3, got %d", view.Output.SpectatorCount)
	}
}

func TestHallRepository_ApplyReadDecision_DeveloperMasksInternalFields(t *testing.T) {
	repo := NewHallRepository(memory.NewHallRepository(nil), testLogger(), newTestBindingDeps(t))
	candidate := service.HallReadCandidate{
		Record: service.HallRecord{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
		Resource: service.Resource{Type: "hall", ID: "hall-1", TenantID: "t1"},
	}
	decision := service.Decision{
		Allow: true,
		Reason: "read_allowed",
		Hash: "hall-read-developer",
		PolicyID: "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{
			"owner_user_id":   service.FieldActionMaskAfterDecrypt,
			"current_film_id": service.FieldActionMaskAfterDecrypt,
		},
	}

	view, err := repo.ApplyReadDecision(withAccess("developer", service.ActionHallRead), candidate, decision)
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.OwnerUserID == "u-admin" || view.Output.CurrentFilmID == "film-1" {
		t.Fatalf("expected masked internal fields, got %+v", view.Output)
	}
	if len(view.FieldsMasked) != 2 {
		t.Fatalf("expected masked field tracking, got %+v", view.FieldsMasked)
	}
}

func TestHallRepository_Create_RequiresAllowDecisionAndReturnsCandidate(t *testing.T) {
	repo := NewHallRepository(memory.NewHallRepository(nil), testLogger(), newTestBindingDeps(t))
	candidate, err := repo.Create(withAccess("admin", service.ActionHallCreate), "t1", service.HallCreateInput{
		Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1",
	}, service.Decision{Allow: true, Reason: "write_allowed", Hash: "hall-write", PolicyID: "cinema-default", PolicyVersion: "v1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if candidate.Record.ID == "" || candidate.Record.Name != "Hall A" {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
}

func TestHallRepository_DCSOffPreservesLegacyBehavior(t *testing.T) {
	repo := NewHallRepository(memory.NewHallRepository(nil), testLogger(), newTestBindingDeps(t))
	candidate := service.HallReadCandidate{
		Record: service.HallRecord{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
		Resource: service.Resource{Type: "hall", ID: "hall-1", TenantID: "t1"},
	}
	view, err := repo.ApplyReadDecision(withAccess("developer", service.ActionHallRead), candidate, service.Decision{
		Allow: true, Reason: "dcs_off", Hash: "hall-dcs-off", PolicyID: "cinema-default", PolicyVersion: "v1",
	})
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.OwnerUserID != "u-admin" || view.Output.CurrentFilmID != "film-1" {
		t.Fatalf("expected passthrough fields when dcs_off, got %+v", view.Output)
	}
}

func TestHallRepository_MissingAccessContextDenied(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), testLogger(), deps)

	_, err := repo.ListCandidates(context.Background(), "t1")
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing access context, got %v", err)
	}
}

func TestHallRepository_AntiBypassDirectRepositoryCallStillEnforced(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), testLogger(), deps)

	candidates, err := repo.ListCandidates(withAccess("developer", service.ActionHallRead), "t1")
	if err != nil {
		t.Fatalf("ListCandidates: %v", err)
	}
	view, err := repo.ApplyReadDecision(withAccess("developer", service.ActionHallRead), candidates[0], service.Decision{
		Allow: true,
		Reason: "read_allowed",
		Hash: "hall-read-developer",
		PolicyID: "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{
			"owner_user_id":   service.FieldActionMaskAfterDecrypt,
			"current_film_id": service.FieldActionMaskAfterDecrypt,
		},
	})
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.OwnerUserID == "u-admin" {
		t.Fatalf("expected repository-level enforcement on direct call, got %v", view.Output.OwnerUserID)
	}
}
