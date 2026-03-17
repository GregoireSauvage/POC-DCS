package secured

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestSpectatorRepository_Create_RequiresAllowDecisionAndReturnsCandidate(t *testing.T) {
	deps := newTestBindingDeps(t)
	repo := NewSpectatorRepository(memory.NewSpectatorRepository(), config.NewDCSRuntime("on", 1), testLogger(), deps)

	candidate, err := repo.Create(withAccess("agent", service.ActionSpectatorCreate), "t1", service.SpectatorCreateInput{
		HallID: "hall-1", Name: "Alice Doe", Age: 31, ExternalID: "TICKET-42",
	}, service.Decision{Allow: true, Reason: "write_allowed", Hash: "spectator-write", PolicyID: "cinema-default", PolicyVersion: "v1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if candidate.Record.ID == "" || candidate.Record.HallID != "hall-1" {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
}

func TestSpectatorRepository_SearchCandidatesByExternalID_ReturnsBindingVerifiedCandidates(t *testing.T) {
	deps := newTestBindingDeps(t)
	spectator := newBoundSpectator(t, deps, "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	raw := memory.NewSpectatorRepository()
	if err := raw.Create(context.Background(), spectator); err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	bindTestSpectators(t, deps, []*domain.Spectator{spectator})

	repo := NewSpectatorRepository(raw, config.NewDCSRuntime("on", 1), testLogger(), deps)
	candidates, err := repo.SearchCandidatesByExternalID(withAccess("admin", service.ActionSearchSpectator), "t1", "TICKET-42", service.Decision{
		Allow: true, Reason: "search_allowed", Hash: "spectator-search", PolicyID: "cinema-default", PolicyVersion: "v1",
	})
	if err != nil {
		t.Fatalf("SearchCandidatesByExternalID: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Record.ID != spectator.ID {
		t.Fatalf("unexpected candidate: %+v", candidates[0])
	}
}

func TestSpectatorRepository_SearchCandidatesByExternalID_DeniesMissingBinding(t *testing.T) {
	deps := newTestBindingDeps(t)
	spectator := newBoundSpectator(t, deps, "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	raw := memory.NewSpectatorRepository()
	if err := raw.Create(context.Background(), spectator); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	repo := NewSpectatorRepository(raw, config.NewDCSRuntime("on", 1), testLogger(), deps)
	_, err := repo.SearchCandidatesByExternalID(withAccess("admin", service.ActionSearchSpectator), "t1", "TICKET-42", service.Decision{
		Allow: true, Reason: "search_allowed", Hash: "spectator-search", PolicyID: "cinema-default", PolicyVersion: "v1",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing binding, got %v", err)
	}
}

func TestSpectatorRepository_ApplyReadDecision_AdminDecrypts(t *testing.T) {
	deps := newTestBindingDeps(t)
	spectator := newBoundSpectator(t, deps, "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	repo := NewSpectatorRepository(memory.NewSpectatorRepository(), config.NewDCSRuntime("on", 1), testLogger(), deps)

	view, err := repo.ApplyReadDecision(withAccess("admin", service.ActionSpectatorRead), service.SpectatorReadCandidate{
		Record: spectator,
		Resource: service.Resource{Type: "spectator", ID: spectator.ID, TenantID: spectator.TenantID},
	}, service.Decision{
		Allow: true,
		Reason: "read_allowed",
		Hash: "spectator-read-admin",
		PolicyID: "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{
			"name":        service.FieldActionDecrypt,
			"age":         service.FieldActionDecrypt,
			"external_id": service.FieldActionDecrypt,
		},
	})
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.ID != spectator.ID {
		t.Fatalf("expected admin raw id, got %v", view.Output.ID)
	}
	if age, ok := view.Output.Age.(int); !ok || age != 31 {
		t.Fatalf("expected decrypted age 31, got %T %v", view.Output.Age, view.Output.Age)
	}
}

func TestSpectatorRepository_ApplyReadDecision_AgentMasksPII(t *testing.T) {
	deps := newTestBindingDeps(t)
	spectator := newBoundSpectator(t, deps, "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	repo := NewSpectatorRepository(memory.NewSpectatorRepository(), config.NewDCSRuntime("on", 1), testLogger(), deps)

	view, err := repo.ApplyReadDecision(withAccess("agent", service.ActionSpectatorRead), service.SpectatorReadCandidate{
		Record: spectator,
		Resource: service.Resource{Type: "spectator", ID: spectator.ID, TenantID: spectator.TenantID},
	}, service.Decision{
		Allow: true,
		Reason: "read_allowed",
		Hash: "spectator-read-agent",
		PolicyID: "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{
			"name":        service.FieldActionMaskAfterDecrypt,
			"age":         service.FieldActionDecrypt,
			"external_id": service.FieldActionMaskAfterDecrypt,
		},
	})
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.ID == spectator.ID {
		t.Fatalf("expected masked spectator id for agent, got %v", view.Output.ID)
	}
	if _, ok := view.Output.Age.(int); !ok {
		t.Fatalf("expected sensitive age decrypted for agent, got %T", view.Output.Age)
	}
	if len(view.FieldsMasked) == 0 {
		t.Fatalf("expected masked PII tracking, got %+v", view.FieldsMasked)
	}
}

func TestSpectatorRepository_DCSOffPreservesLegacyBehavior(t *testing.T) {
	deps := newTestBindingDeps(t)
	spectator := newBoundSpectator(t, deps, "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	repo := NewSpectatorRepository(memory.NewSpectatorRepository(), config.NewDCSRuntime("off", 1), testLogger(), deps)

	view, err := repo.ApplyReadDecision(withAccess("agent", service.ActionSpectatorRead), service.SpectatorReadCandidate{
		Record: spectator,
		Resource: service.Resource{Type: "spectator", ID: spectator.ID, TenantID: spectator.TenantID},
	}, service.Decision{
		Allow: true, Reason: "dcs_off", Hash: "spectator-dcs-off", PolicyID: "cinema-default", PolicyVersion: "v1",
	})
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.ID != spectator.ID {
		t.Fatalf("expected raw id passthrough when dcs_off, got %v", view.Output.ID)
	}
}

func TestSpectatorRepository_MissingAccessContextDenied(t *testing.T) {
	repo := NewSpectatorRepository(memory.NewSpectatorRepository(), config.NewDCSRuntime("on", 1), testLogger(), newTestBindingDeps(t))

	_, err := repo.SearchCandidatesByExternalID(context.Background(), "t1", "TICKET-42", service.Decision{
		Allow: true, Reason: "search_allowed", Hash: "spectator-search", PolicyID: "cinema-default", PolicyVersion: "v1",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing access context, got %v", err)
	}
}

func TestSpectatorRepository_AntiBypassDirectRepositoryCallStillEnforced(t *testing.T) {
	deps := newTestBindingDeps(t)
	spectator := newBoundSpectator(t, deps, "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	raw := memory.NewSpectatorRepository()
	if err := raw.Create(context.Background(), spectator); err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	bindTestSpectators(t, deps, []*domain.Spectator{spectator})

	repo := NewSpectatorRepository(raw, config.NewDCSRuntime("on", 1), testLogger(), deps)
	candidates, err := repo.SearchCandidatesByExternalID(withAccess("agent", service.ActionSearchSpectator), "t1", "TICKET-42", service.Decision{
		Allow: true, Reason: "search_allowed", Hash: "spectator-search", PolicyID: "cinema-default", PolicyVersion: "v1",
	})
	if err != nil {
		t.Fatalf("SearchCandidatesByExternalID: %v", err)
	}
	view, err := repo.ApplyReadDecision(withAccess("agent", service.ActionSpectatorRead), candidates[0], service.Decision{
		Allow: true,
		Reason: "read_allowed",
		Hash: "spectator-read-agent",
		PolicyID: "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{
			"name":        service.FieldActionMaskAfterDecrypt,
			"age":         service.FieldActionDecrypt,
			"external_id": service.FieldActionMaskAfterDecrypt,
		},
	})
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if view.Output.ID == spectator.ID {
		t.Fatalf("expected enforced masked id on direct repository call, got %v", view.Output.ID)
	}
}

func TestSpectatorRepository_SearchCandidatesByExternalIDComputesLookupFromCleartext(t *testing.T) {
	var receivedLookup []byte
	raw := &fakeRawSpectatorRepository{
		findByExternalIDLookup: func(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error) {
			receivedLookup = append([]byte(nil), lookup...)
			return nil, nil
		},
	}

	deps := newTestBindingDeps(t)
	repo := NewSpectatorRepository(raw, config.NewDCSRuntime("on", 1), testLogger(), deps)
	_, err := repo.SearchCandidatesByExternalID(withAccess("admin", service.ActionSearchSpectator), "t1", "TICKET-42", service.Decision{
		Allow: true, Reason: "search_allowed", Hash: "spectator-search", PolicyID: "cinema-default", PolicyVersion: "v1",
	})
	if err != nil {
		t.Fatalf("SearchCandidatesByExternalID: %v", err)
	}

	pepper, err := deps.Crypto.GetPepper(context.Background(), service.DefaultSpectatorPepperPath)
	if err != nil {
		t.Fatalf("GetPepper: %v", err)
	}
	expectedLookup := service.ComputeHMACLookup(pepper, service.NormalizeExternalID("TICKET-42"))
	if string(receivedLookup) != string(expectedLookup) {
		t.Fatalf("expected lookup derived from cleartext external_id, got %x want %x", receivedLookup, expectedLookup)
	}
}

func newBoundSpectator(t *testing.T, deps BindingDependencies, spectatorID string, externalID string) *domain.Spectator {
	t.Helper()

	nameCT, err := deps.Crypto.Encrypt(context.Background(), "Alice Doe")
	if err != nil {
		t.Fatalf("encrypt name: %v", err)
	}
	ageCT, err := deps.Crypto.Encrypt(context.Background(), strconv.Itoa(31))
	if err != nil {
		t.Fatalf("encrypt age: %v", err)
	}
	externalIDCT, err := deps.Crypto.Encrypt(context.Background(), externalID)
	if err != nil {
		t.Fatalf("encrypt external_id: %v", err)
	}
	pepper, err := deps.Crypto.GetPepper(context.Background(), service.DefaultSpectatorPepperPath)
	if err != nil {
		t.Fatalf("get pepper: %v", err)
	}

	return &domain.Spectator{
		TenantID:         "t1",
		ID:               spectatorID,
		HallID:           "hall-1",
		NameCT:           nameCT,
		AgeCT:            ageCT,
		ExternalIDCT:     externalIDCT,
		ExternalIDLookup: service.ComputeHMACLookup(pepper, service.NormalizeExternalID(externalID)),
	}
}

type fakeRawSpectatorRepository struct {
	create                 func(ctx context.Context, spectator *domain.Spectator) error
	findByExternalIDLookup func(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error)
	countByHall            func(ctx context.Context, tenantID, hallID string) (int, error)
}

func (f *fakeRawSpectatorRepository) Create(ctx context.Context, spectator *domain.Spectator) error {
	if f.create == nil {
		return nil
	}
	return f.create(ctx, spectator)
}

func (f *fakeRawSpectatorRepository) FindByExternalIDLookup(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error) {
	if f.findByExternalIDLookup == nil {
		return nil, nil
	}
	return f.findByExternalIDLookup(ctx, tenantID, lookup)
}

func (f *fakeRawSpectatorRepository) CountByHall(ctx context.Context, tenantID, hallID string) (int, error) {
	if f.countByHall == nil {
		return 0, nil
	}
	return f.countByHall(ctx, tenantID, hallID)
}
