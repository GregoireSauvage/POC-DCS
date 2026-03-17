package secured

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	infrakms "github.com/neoweyss/poc-dcs/backend-go/internal/infra/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestFilmRepository_ListCandidates_ReturnsBindingVerifiedCandidates(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	ciphertext, err := deps.Crypto.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	records := []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext}}
	raw := memory.NewFilmRepository(records)
	bindTestFilmRecords(t, deps, records)
	repo := NewFilmRepository(raw, testLogger(), deps)

	candidates, err := repo.ListCandidates(withAccess("admin", service.ActionFilmRead), "t1")
	if err != nil {
		t.Fatalf("ListCandidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].Record.ID != "film-1" || candidates[0].Resource.ID != "film-1" {
		t.Fatalf("unexpected candidate: %+v", candidates[0])
	}
}

func TestFilmRepository_ListCandidates_DeniesMissingBinding(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	ciphertext, err := deps.Crypto.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	raw := memory.NewFilmRepository([]service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext}})
	repo := NewFilmRepository(raw, testLogger(), deps)

	_, err = repo.ListCandidates(withAccess("admin", service.ActionFilmRead), "t1")
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing binding, got %v", err)
	}
}

func TestFilmRepository_ListCandidates_DeniesInvalidBinding(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	initialCT, err := deps.Crypto.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt initial: %v", err)
	}
	updatedCT, err := deps.Crypto.Encrypt(context.Background(), "150")
	if err != nil {
		t.Fatalf("encrypt updated: %v", err)
	}

	records := []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: initialCT}}
	raw := memory.NewFilmRepository(records)
	bindTestFilmRecords(t, deps, records)
	if _, err := raw.UpdateTimeCiphertext(context.Background(), "t1", "film-1", updatedCT); err != nil {
		t.Fatalf("tamper raw record: %v", err)
	}
	repo := NewFilmRepository(raw, testLogger(), deps)

	_, err = repo.ListCandidates(withAccess("admin", service.ActionFilmRead), "t1")
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on invalid binding, got %v", err)
	}
}

func TestFilmRepository_ApplyReadDecision_AdminDecrypts(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	ciphertext, err := deps.Crypto.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	repo := NewFilmRepository(memory.NewFilmRepository(nil), testLogger(), deps)

	candidate := service.FilmReadCandidate{
		Record:   service.FilmRecord{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
		Resource: service.Resource{Type: "film", ID: "film-1", TenantID: "t1"},
	}
	decision := service.Decision{
		Allow:         true,
		Reason:        "read_allowed",
		Hash:          "read-admin",
		PolicyID:      "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{
			"time_elapsed": service.FieldActionDecrypt,
		},
	}

	view, err := repo.ApplyReadDecision(withAccess("admin", service.ActionFilmRead), candidate, decision)
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if timeElapsed, ok := view.Output.TimeElapsed.(int); !ok || timeElapsed != 120 {
		t.Fatalf("expected decrypted int 120, got %T %v", view.Output.TimeElapsed, view.Output.TimeElapsed)
	}
	if !containsField(view.FieldsDecrypted, "time_elapsed") {
		t.Fatalf("expected decrypted field tracking, got %+v", view.FieldsDecrypted)
	}
}

func TestFilmRepository_ApplyReadDecision_DeveloperMasks(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	ciphertext, err := deps.Crypto.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	repo := NewFilmRepository(memory.NewFilmRepository(nil), testLogger(), deps)

	candidate := service.FilmReadCandidate{
		Record:   service.FilmRecord{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
		Resource: service.Resource{Type: "film", ID: "film-1", TenantID: "t1"},
	}
	decision := service.Decision{
		Allow:         true,
		Reason:        "read_allowed",
		Hash:          "read-developer",
		PolicyID:      "cinema-default",
		PolicyVersion: "v1",
		FieldActions: map[string]service.FieldAction{
			"time_elapsed": service.FieldActionMaskAfterDecrypt,
		},
	}

	view, err := repo.ApplyReadDecision(withAccess("developer", service.ActionFilmRead), candidate, decision)
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if masked, ok := view.Output.TimeElapsed.(string); !ok || masked != "1***" {
		t.Fatalf("expected masked value 1***, got %T %v", view.Output.TimeElapsed, view.Output.TimeElapsed)
	}
	if !containsField(view.FieldsMasked, "time_elapsed") {
		t.Fatalf("expected masked field tracking, got %+v", view.FieldsMasked)
	}
}

func TestFilmRepository_ApplyReadDecision_DCSOffDecryptsWithoutFieldTracking(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	ciphertext, err := deps.Crypto.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	repo := NewFilmRepository(memory.NewFilmRepository(nil), testLogger(), deps)

	candidate := service.FilmReadCandidate{
		Record:   service.FilmRecord{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
		Resource: service.Resource{Type: "film", ID: "film-1", TenantID: "t1"},
	}
	decision := service.Decision{Allow: true, Reason: "dcs_off", Hash: "dcs-off", PolicyID: "cinema-default", PolicyVersion: "v1"}

	view, err := repo.ApplyReadDecision(withAccess("developer", service.ActionFilmRead), candidate, decision)
	if err != nil {
		t.Fatalf("ApplyReadDecision: %v", err)
	}
	if timeElapsed, ok := view.Output.TimeElapsed.(int); !ok || timeElapsed != 120 {
		t.Fatalf("expected decrypted int 120, got %T %v", view.Output.TimeElapsed, view.Output.TimeElapsed)
	}
	if len(view.FieldsDecrypted) != 0 || len(view.FieldsMasked) != 0 || len(view.FieldsDenied) != 0 {
		t.Fatalf("expected no field tracking in dcs_off, got %+v %+v %+v", view.FieldsDecrypted, view.FieldsMasked, view.FieldsDenied)
	}
}

func TestFilmRepository_Create_RequiresAllowDecisionAndReturnsCandidate(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	raw := memory.NewFilmRepository(nil)
	repo := NewFilmRepository(raw, testLogger(), deps)

	candidate, err := repo.Create(withAccess("admin", service.ActionFilmCreate), "t1", service.FilmCreateInput{Title: "Memento", TimeElapsed: 98}, service.Decision{Allow: true, Reason: "write_allowed", Hash: "write-create", PolicyID: "cinema-default", PolicyVersion: "v1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if candidate.Record.Title != "Memento" || candidate.Record.ID == "" {
		t.Fatalf("unexpected candidate after create: %+v", candidate)
	}
}

func TestFilmRepository_UpdateTime_RequiresAllowDecisionAndReturnsCandidate(t *testing.T) {
	deps := newFilmRepoTestDeps(t)
	initialCT, err := deps.Crypto.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt initial: %v", err)
	}
	records := []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: initialCT}}
	raw := memory.NewFilmRepository(records)
	bindTestFilmRecords(t, deps, records)
	repo := NewFilmRepository(raw, testLogger(), deps)

	candidate, err := repo.UpdateTime(withAccess("admin", service.ActionFilmUpdateTime), "t1", "film-1", 150, service.Decision{Allow: true, Reason: "write_allowed", Hash: "write-update", PolicyID: "cinema-default", PolicyVersion: "v1"})
	if err != nil {
		t.Fatalf("UpdateTime: %v", err)
	}
	if candidate.Record.ID != "film-1" {
		t.Fatalf("unexpected candidate after update: %+v", candidate)
	}
}

func newFilmRepoTestDeps(t *testing.T) BindingDependencies {
	t.Helper()
	deps := newTestBindingDeps(t)
	deps.Crypto = infrakms.NewLocalClient()
	deps.ClassificationReader = service.NewStaticClassificationReader(map[string][]domain.FieldClassification{
		"film": {
			{ResourceType: "film", FieldName: "title", Classification: "PUBLIC"},
			{ResourceType: "film", FieldName: "time_elapsed", Classification: "SENSITIVE"},
		},
	})
	return deps
}

func containsField(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
