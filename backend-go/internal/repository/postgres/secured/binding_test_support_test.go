package secured

import (
	"context"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	infrabinding "github.com/neoweyss/poc-dcs/backend-go/internal/infra/binding"
	infrakms "github.com/neoweyss/poc-dcs/backend-go/internal/infra/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func newTestBindingDeps(t *testing.T) BindingDependencies {
	t.Helper()
	cfg := config.DefaultDCSConfig()
	manager := infrabinding.NewManager(infrabinding.Config{
		ProfileID:      cfg.Binding.ProfileID,
		ProofAlgorithm: cfg.Binding.ProofAlgorithm,
		KeyID:          cfg.Binding.KeyID,
		Secret:         []byte("test-binding-secret"),
	})
	labelIssuer := service.NewServerLabelIssuer(
		config.NewClassificationPolicy(cfg),
		service.NewStaticClassificationReader(map[string][]domain.FieldClassification{
			"film": {
				{ResourceType: "film", FieldName: "title", Classification: "PUBLIC"},
				{ResourceType: "film", FieldName: "time_elapsed", Classification: "SENSITIVE"},
			},
			"hall": {
				{ResourceType: "hall", FieldName: "name", Classification: "PUBLIC"},
				{ResourceType: "hall", FieldName: "owner_user_id", Classification: "INTERNAL"},
				{ResourceType: "hall", FieldName: "current_film_id", Classification: "INTERNAL"},
			},
			"spectator": {
				{ResourceType: "spectator", FieldName: "name", Classification: "PII"},
				{ResourceType: "spectator", FieldName: "age", Classification: "SENSITIVE"},
				{ResourceType: "spectator", FieldName: "external_id", Classification: "PII"},
			},
		}),
		map[string]service.Classification{
			"film":      service.ClassificationSensitive,
			"hall":      service.ClassificationInternal,
			"spectator": service.ClassificationPII,
		},
	)
	return BindingDependencies{
		Store:       memory.NewBindingRepository(),
		Verifier:    manager,
		Issuer:      manager,
		LabelIssuer: labelIssuer,
		Crypto:      infrakms.NewLocalClient(),
	}
}

func bindTestFilmRecords(t *testing.T, deps BindingDependencies, records []service.FilmRecord) {
	t.Helper()
	for _, record := range records {
		mustBindResource(t, deps, service.Resource{Type: "film", ID: record.ID, TenantID: record.TenantID}, buildFilmPayload(record))
	}
}

func bindTestHalls(t *testing.T, deps BindingDependencies, halls []domain.Hall) {
	t.Helper()
	for _, hall := range halls {
		h := hall
		mustBindResource(t, deps, buildHallResource(&h), buildHallPayload(service.HallRecord{TenantID: h.TenantID, ID: h.ID, Name: h.Name, OwnerUserID: h.OwnerUserID, CurrentFilmID: h.CurrentFilmID}))
	}
}

func bindTestSpectators(t *testing.T, deps BindingDependencies, spectators []*domain.Spectator) {
	t.Helper()
	for _, spectator := range spectators {
		mustBindResource(t, deps, buildSpectatorResource(spectator), buildSpectatorPayload(spectator))
	}
}

func mustBindResource(t *testing.T, deps BindingDependencies, resource service.Resource, payload any) {
	t.Helper()
	access := service.AccessContext{Principal: service.Principal{TenantID: resource.TenantID, UserID: "u-admin", Role: "admin"}, Request: service.RequestContext{RequestID: "seed", Channel: "seed", Purpose: "test", Env: "test"}}
	label, err := deps.LabelIssuer.Issue(context.Background(), access, resource)
	if err != nil {
		t.Fatalf("issue label: %v", err)
	}
	binding, err := deps.Issuer.Create(context.Background(), payload, label)
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if err := deps.Store.Upsert(context.Background(), service.ResourceBinding{TenantID: resource.TenantID, ResourceType: resource.Type, ResourceID: resource.ID, Label: label, Binding: binding}); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
}
