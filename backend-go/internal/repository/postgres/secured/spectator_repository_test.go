package secured

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestSpectatorRepository_CreateReturnsSecureView(t *testing.T) {
	policyEnforcer := newSecuredPolicyEnforcer(t, "on")
	encrypted, err := policyEnforcer.EnforceSpectatorCreate(context.Background(), withAccessPrincipal("agent"), withAccessRequest(), service.SpectatorCreatePlain{
		HallID:     "hall-1",
		Name:       "Alice Doe",
		Age:        31,
		ExternalID: "TICKET-42",
	})
	if err != nil {
		t.Fatalf("EnforceSpectatorCreate: %v", err)
	}

	repo := NewSpectatorRepository(memory.NewSpectatorRepository(), policyEnforcer, runtime.New("on", 1), testLogger())
	view, err := repo.Create(withAccess("agent", service.ActionSpectatorCreate), &domain.Spectator{
		TenantID:         "t1",
		ID:               "550e8400-e29b-41d4-a716-446655440000",
		HallID:           encrypted.HallID,
		NameCT:           encrypted.NameCT,
		AgeCT:            encrypted.AgeCT,
		ExternalIDCT:     encrypted.ExternalIDCT,
		ExternalIDLookup: encrypted.ExternalIDLookup,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.Output.ID == "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("expected non-admin id masking on create response, got %v", view.Output.ID)
	}
	if _, ok := view.Output.Age.(int); !ok {
		t.Fatalf("expected agent to see decrypted age, got %T", view.Output.Age)
	}
	if len(view.FieldsMasked) == 0 {
		t.Fatalf("expected masked PII tracking, got %+v", view.FieldsMasked)
	}
}

func TestSpectatorRepository_SearchByExternalID_AdminDecrypts(t *testing.T) {
	policyEnforcer := newSecuredPolicyEnforcer(t, "on")
	spectator := newEncryptedSpectator(t, policyEnforcer, "admin", "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	raw := memory.NewSpectatorRepository()
	if err := raw.Create(context.Background(), spectator); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	repo := NewSpectatorRepository(raw, policyEnforcer, runtime.New("on", 1), testLogger())
	views, err := repo.SearchByExternalID(withAccess("admin", service.ActionSearchSpectator), "t1", "TICKET-42")
	if err != nil {
		t.Fatalf("SearchByExternalID: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 spectator, got %d", len(views))
	}
	if views[0].Output.ID != spectator.ID {
		t.Fatalf("expected admin to keep raw id, got %v", views[0].Output.ID)
	}
	if age, ok := views[0].Output.Age.(int); !ok || age != 31 {
		t.Fatalf("expected decrypted age 31, got %T %v", views[0].Output.Age, views[0].Output.Age)
	}
}

func TestSpectatorRepository_SearchByExternalID_AgentMasksPII(t *testing.T) {
	policyEnforcer := newSecuredPolicyEnforcer(t, "on")
	spectator := newEncryptedSpectator(t, policyEnforcer, "admin", "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	raw := memory.NewSpectatorRepository()
	if err := raw.Create(context.Background(), spectator); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	repo := NewSpectatorRepository(raw, policyEnforcer, runtime.New("on", 1), testLogger())
	views, err := repo.SearchByExternalID(withAccess("agent", service.ActionSearchSpectator), "t1", "TICKET-42")
	if err != nil {
		t.Fatalf("SearchByExternalID: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 spectator, got %d", len(views))
	}
	if views[0].Output.ID == spectator.ID {
		t.Fatalf("expected masked spectator id for agent, got %v", views[0].Output.ID)
	}
	if _, ok := views[0].Output.Age.(int); !ok {
		t.Fatalf("expected sensitive age decrypted for agent, got %T", views[0].Output.Age)
	}
	if len(views[0].FieldsMasked) == 0 {
		t.Fatalf("expected masked PII tracking, got %+v", views[0].FieldsMasked)
	}
}

func TestSpectatorRepository_DCSOffPreservesLegacyBehavior(t *testing.T) {
	policyEnforcer := newSecuredPolicyEnforcer(t, "off")
	spectator := newEncryptedSpectator(t, policyEnforcer, "admin", "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	raw := memory.NewSpectatorRepository()
	if err := raw.Create(context.Background(), spectator); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	repo := NewSpectatorRepository(raw, policyEnforcer, runtime.New("off", 1), testLogger())
	views, err := repo.SearchByExternalID(withAccess("agent", service.ActionSearchSpectator), "t1", "TICKET-42")
	if err != nil {
		t.Fatalf("SearchByExternalID: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 spectator, got %d", len(views))
	}
	if views[0].Output.ID != spectator.ID {
		t.Fatalf("expected raw id passthrough when dcs_off, got %v", views[0].Output.ID)
	}
}

func TestSpectatorRepository_MissingAccessContextDenied(t *testing.T) {
	repo := NewSpectatorRepository(memory.NewSpectatorRepository(), newSecuredPolicyEnforcer(t, "on"), runtime.New("on", 1), testLogger())

	_, err := repo.SearchByExternalID(context.Background(), "t1", "TICKET-42")
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing access context, got %v", err)
	}
}

func TestSpectatorRepository_AntiBypassDirectRepositoryCallStillEnforced(t *testing.T) {
	policyEnforcer := newSecuredPolicyEnforcer(t, "on")
	spectator := newEncryptedSpectator(t, policyEnforcer, "admin", "550e8400-e29b-41d4-a716-446655440000", "TICKET-42")
	raw := memory.NewSpectatorRepository()
	if err := raw.Create(context.Background(), spectator); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	repo := NewSpectatorRepository(raw, policyEnforcer, runtime.New("on", 1), testLogger())
	views, err := repo.SearchByExternalID(withAccess("agent", service.ActionSearchSpectator), "t1", "TICKET-42")
	if err != nil {
		t.Fatalf("SearchByExternalID: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 spectator, got %d", len(views))
	}
	if views[0].Output.ID == spectator.ID {
		t.Fatalf("expected enforced masked id on direct repository call, got %v", views[0].Output.ID)
	}
}

func TestSpectatorRepository_SearchByExternalIDComputesLookupFromCleartext(t *testing.T) {
	policyEnforcer := newSecuredPolicyEnforcer(t, "on")
	var receivedLookup []byte
	raw := &fakeRawSpectatorRepository{
		findByExternalIDLookup: func(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error) {
			receivedLookup = append([]byte(nil), lookup...)
			return nil, nil
		},
	}

	repo := NewSpectatorRepository(raw, policyEnforcer, runtime.New("on", 1), testLogger())
	_, err := repo.SearchByExternalID(withAccess("admin", service.ActionSearchSpectator), "t1", "TICKET-42")
	if err != nil {
		t.Fatalf("SearchByExternalID: %v", err)
	}

	pepper, err := policyEnforcer.GetPepper(context.Background(), service.DefaultSpectatorPepperPath)
	if err != nil {
		t.Fatalf("GetPepper: %v", err)
	}
	expectedLookup := kms.ComputeHMACLookup(pepper, kms.NormalizeExternalID("TICKET-42"))
	if string(receivedLookup) != string(expectedLookup) {
		t.Fatalf("expected lookup derived from cleartext external_id, got %x want %x", receivedLookup, expectedLookup)
	}
}

func newEncryptedSpectator(t *testing.T, policyEnforcer service.PolicyEnforcer, role string, spectatorID string, externalID string) *domain.Spectator {
	t.Helper()

	encrypted, err := policyEnforcer.EnforceSpectatorCreate(context.Background(), withAccessPrincipal(role), withAccessRequest(), service.SpectatorCreatePlain{
		HallID:     "hall-1",
		Name:       "Alice Doe",
		Age:        31,
		ExternalID: externalID,
	})
	if err != nil {
		t.Fatalf("EnforceSpectatorCreate: %v", err)
	}

	return &domain.Spectator{
		TenantID:         "t1",
		ID:               spectatorID,
		HallID:           encrypted.HallID,
		NameCT:           encrypted.NameCT,
		AgeCT:            encrypted.AgeCT,
		ExternalIDCT:     encrypted.ExternalIDCT,
		ExternalIDLookup: encrypted.ExternalIDLookup,
	}
}

func withAccessPrincipal(role string) service.Principal {
	return service.Principal{
		TenantID: "t1",
		UserID:   "u-" + role,
		Username: role,
		Role:     role,
		Scopes:   []string{"cinema"},
	}
}

func withAccessRequest() service.RequestContext {
	return service.RequestContext{
		RequestID:   "req-1",
		ClientIP:    "127.0.0.1",
		Channel:     "web",
		Purpose:     "cinema_ops",
		DeviceTrust: 1.0,
		Env:         "test",
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
