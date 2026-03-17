package secured

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	legacycache "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/enforcer"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	legacyruntime "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	legacytypes "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	infrakms "github.com/neoweyss/poc-dcs/backend-go/internal/infra/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	serviceauth "github.com/neoweyss/poc-dcs/backend-go/internal/service/authorization"
)

func TestHallRepository_ListByTenant_AdminSeesInternalFields(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), newSecuredPolicyEnforcer(t, "on"), testLogger(), deps)

	views, err := repo.ListByTenant(withAccess("admin", service.ActionHallRead), "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 hall, got %d", len(views))
	}
	if got := views[0].Output.OwnerUserID; got != "u-admin" {
		t.Fatalf("expected owner_user_id to remain visible, got %v", got)
	}
	if got := views[0].Output.CurrentFilmID; got != "film-1" {
		t.Fatalf("expected current_film_id to remain visible, got %v", got)
	}
}

func TestHallRepository_ListByTenant_DeveloperMasksInternalFields(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), newSecuredPolicyEnforcer(t, "on"), testLogger(), deps)

	views, err := repo.ListByTenant(withAccess("developer", service.ActionHallRead), "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 hall, got %d", len(views))
	}
	if views[0].Output.OwnerUserID == "u-admin" {
		t.Fatalf("expected owner_user_id to be masked, got %v", views[0].Output.OwnerUserID)
	}
	if views[0].Output.CurrentFilmID == "film-1" {
		t.Fatalf("expected current_film_id to be masked, got %v", views[0].Output.CurrentFilmID)
	}
	if len(views[0].FieldsMasked) == 0 {
		t.Fatalf("expected masked field tracking, got %+v", views[0].FieldsMasked)
	}
}

func TestHallRepository_CreateReturnsSecureView(t *testing.T) {
	repo := NewHallRepository(memory.NewHallRepository(nil), newSecuredPolicyEnforcer(t, "on"), testLogger(), newTestBindingDeps(t))

	view, err := repo.Create(withAccess("developer", service.ActionHallCreate), &domain.Hall{
		TenantID:      "t1",
		ID:            "hall-1",
		Name:          "Hall A",
		OwnerUserID:   "u-admin",
		CurrentFilmID: "film-1",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.Output.Name == nil || *view.Output.Name != "Hall A" {
		t.Fatalf("expected public hall name to remain visible, got %+v", view.Output.Name)
	}
	if view.Output.OwnerUserID == "u-admin" {
		t.Fatalf("expected owner_user_id to be read-shaped on create response")
	}
}

func TestHallRepository_DCSOffPreservesLegacyBehavior(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), newSecuredPolicyEnforcer(t, "off"), testLogger(), deps)

	views, err := repo.ListByTenant(withAccess("developer", service.ActionHallRead), "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 hall, got %d", len(views))
	}
	if views[0].Output.OwnerUserID != "u-admin" || views[0].Output.CurrentFilmID != "film-1" {
		t.Fatalf("expected passthrough fields when dcs_off, got %+v", views[0].Output)
	}
}

func TestHallRepository_MissingAccessContextDenied(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), newSecuredPolicyEnforcer(t, "on"), testLogger(), deps)

	_, err := repo.ListByTenant(context.Background(), "t1")
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing access context, got %v", err)
	}
}

func TestHallRepository_AntiBypassDirectRepositoryCallStillEnforced(t *testing.T) {
	seed := []domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}}
	deps := newTestBindingDeps(t)
	bindTestHalls(t, deps, seed)
	repo := NewHallRepository(memory.NewHallRepository(seed), newSecuredPolicyEnforcer(t, "on"), testLogger(), deps)

	views, err := repo.ListByTenant(withAccess("developer", service.ActionHallRead), "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 hall, got %d", len(views))
	}
	if views[0].Output.OwnerUserID == "u-admin" {
		t.Fatalf("expected repository-level enforcement on direct call, got %v", views[0].Output.OwnerUserID)
	}
}

func newSecuredPolicyEnforcer(t *testing.T, dcsMode string) service.PolicyEnforcer {
	t.Helper()

	rt := legacyruntime.New(dcsMode, 1)
	cm := legacycache.NewManager(rt, legacycache.Options{
		MaxEntries:        100,
		ClassificationTTL: 60,
		PDPTTL:            60,
		KMSTTL:            60,
		PepperTTL:         60,
	})
	kmsClient := infrakms.NewLocalClient()
	classificationStore := &pip.StaticClassificationStore{
		ByResource: map[string]map[string]legacytypes.Classification{
			"film": {
				"title":        legacytypes.ClassificationPublic,
				"time_elapsed": legacytypes.ClassificationSensitive,
			},
			"hall": {
				"name":            legacytypes.ClassificationPublic,
				"owner_user_id":   legacytypes.ClassificationInternal,
				"current_film_id": legacytypes.ClassificationInternal,
			},
			"spectator": {
				"name":        legacytypes.ClassificationPII,
				"age":         legacytypes.ClassificationSensitive,
				"external_id": legacytypes.ClassificationPII,
			},
		},
	}
	provider := pip.NewProvider(rt, cm, classificationStore, pip.Config{
		Env:            "test",
		Channel:        "web",
		Purpose:        "access",
		DeviceTrust:    1.0,
		ClientIPHeader: "X-Forwarded-For",
	})
	cfg := config.DefaultDCSConfig()
	policy := config.NewClassificationPolicy(cfg)
	authorizer := serviceauth.NewAuthorizer(rt, serviceauth.NewPDP(policy))
	filmApplier := pep.NewFilmApplier(rt, kmsClient)
	spectatorApplier := pep.NewSpectatorApplier(kmsClient)

	return enforcer.New(provider, authorizer, filmApplier, spectatorApplier, kmsClient, "")
}
