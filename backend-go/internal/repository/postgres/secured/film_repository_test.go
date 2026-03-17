package secured

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	legacycache "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/enforcer"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	legacyruntime "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	legacytypes "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	infrakms "github.com/neoweyss/poc-dcs/backend-go/internal/infra/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	serviceauth "github.com/neoweyss/poc-dcs/backend-go/internal/service/authorization"
)

func TestFilmRepository_ListByTenant_AdminDecrypts(t *testing.T) {
	policyEnforcer := newFilmPolicyEnforcer(t, "on")
	ciphertext, err := policyEnforcer.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	raw := memory.NewFilmRepository([]service.FilmRecord{
		{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
	})
	bindingDeps := newTestBindingDeps(t)
	bindTestFilmRecords(t, bindingDeps, []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext}})
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), bindingDeps)

	ctx := withAccess("admin", service.ActionFilmRead)
	views, err := repo.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 film, got %d", len(views))
	}
	if timeElapsed, ok := views[0].Output.TimeElapsed.(int); !ok || timeElapsed != 120 {
		t.Fatalf("expected decrypted int 120, got %T %v", views[0].Output.TimeElapsed, views[0].Output.TimeElapsed)
	}
	if len(views[0].FieldsDecrypted) != 1 || views[0].FieldsDecrypted[0] != "time_elapsed" {
		t.Fatalf("expected decrypted field tracking, got %+v", views[0].FieldsDecrypted)
	}
}

func TestFilmRepository_ListByTenant_DeveloperMasks(t *testing.T) {
	policyEnforcer := newFilmPolicyEnforcer(t, "on")
	ciphertext, err := policyEnforcer.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	raw := memory.NewFilmRepository([]service.FilmRecord{
		{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
	})
	bindingDeps := newTestBindingDeps(t)
	bindTestFilmRecords(t, bindingDeps, []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext}})
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), bindingDeps)

	ctx := withAccess("developer", service.ActionFilmRead)
	views, err := repo.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 film, got %d", len(views))
	}
	if masked, ok := views[0].Output.TimeElapsed.(string); !ok || masked != "1***" {
		t.Fatalf("expected masked time_elapsed 1***, got %T %v", views[0].Output.TimeElapsed, views[0].Output.TimeElapsed)
	}
	if len(views[0].FieldsMasked) != 1 || views[0].FieldsMasked[0] != "time_elapsed" {
		t.Fatalf("expected masked field tracking, got %+v", views[0].FieldsMasked)
	}
}

func TestFilmRepository_CreateReturnsSecureView(t *testing.T) {
	policyEnforcer := newFilmPolicyEnforcer(t, "on")
	ciphertext, err := policyEnforcer.Encrypt(context.Background(), "98")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	raw := memory.NewFilmRepository(nil)
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), newTestBindingDeps(t))

	ctx := withAccess("developer", service.ActionFilmCreate)
	view, err := repo.Create(ctx, "t1", "Memento", ciphertext)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := view.Output.TimeElapsed.(string); !ok {
		t.Fatalf("expected masked string time_elapsed, got %T", view.Output.TimeElapsed)
	}
	if view.Output.TimeElapsed == ciphertext {
		t.Fatalf("expected read-shaped response, got raw ciphertext")
	}
}

func TestFilmRepository_UpdateTimeCiphertextReturnsSecureView(t *testing.T) {
	policyEnforcer := newFilmPolicyEnforcer(t, "on")
	initialCT, err := policyEnforcer.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt initial: %v", err)
	}
	updatedCT, err := policyEnforcer.Encrypt(context.Background(), "150")
	if err != nil {
		t.Fatalf("encrypt updated: %v", err)
	}

	raw := memory.NewFilmRepository([]service.FilmRecord{
		{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: initialCT},
	})
	bindingDeps := newTestBindingDeps(t)
	bindTestFilmRecords(t, bindingDeps, []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: initialCT}})
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), bindingDeps)

	ctx := withAccess("admin", service.ActionFilmUpdateTime)
	view, err := repo.UpdateTimeCiphertext(ctx, "t1", "film-1", updatedCT)
	if err != nil {
		t.Fatalf("UpdateTimeCiphertext: %v", err)
	}
	if timeElapsed, ok := view.Output.TimeElapsed.(int); !ok || timeElapsed != 150 {
		t.Fatalf("expected decrypted int 150, got %T %v", view.Output.TimeElapsed, view.Output.TimeElapsed)
	}
	if view.Output.TimeElapsed == updatedCT {
		t.Fatalf("expected read-shaped response, got raw ciphertext")
	}
}

func TestFilmRepository_DCSOffPreservesLegacyBehavior(t *testing.T) {
	policyEnforcer := newFilmPolicyEnforcer(t, "off")
	ciphertext, err := policyEnforcer.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	raw := memory.NewFilmRepository([]service.FilmRecord{
		{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
	})
	bindingDeps := newTestBindingDeps(t)
	bindTestFilmRecords(t, bindingDeps, []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext}})
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), bindingDeps)

	ctx := withAccess("developer", service.ActionFilmRead)
	views, err := repo.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 film, got %d", len(views))
	}
	if got, ok := views[0].Output.TimeElapsed.(string); !ok || got != ciphertext {
		t.Fatalf("expected ciphertext passthrough when dcs_off, got %T %v", views[0].Output.TimeElapsed, views[0].Output.TimeElapsed)
	}
}

func TestFilmRepository_MissingAccessContextDenied(t *testing.T) {
	policyEnforcer := newFilmPolicyEnforcer(t, "on")
	ciphertext, err := policyEnforcer.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	raw := memory.NewFilmRepository([]service.FilmRecord{
		{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
	})
	bindingDeps := newTestBindingDeps(t)
	bindTestFilmRecords(t, bindingDeps, []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext}})
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), bindingDeps)

	_, err = repo.ListByTenant(context.Background(), "t1")
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected forbidden on missing access context, got %v", err)
	}
}

func TestFilmRepository_AntiBypassDirectRepositoryCallStillEnforced(t *testing.T) {
	policyEnforcer := newFilmPolicyEnforcer(t, "on")
	ciphertext, err := policyEnforcer.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	raw := memory.NewFilmRepository([]service.FilmRecord{
		{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext},
	})
	bindingDeps := newTestBindingDeps(t)
	bindTestFilmRecords(t, bindingDeps, []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: ciphertext}})
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), bindingDeps)

	ctx := withAccess("developer", service.ActionFilmRead)
	views, err := repo.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected 1 film, got %d", len(views))
	}
	if masked, ok := views[0].Output.TimeElapsed.(string); !ok || masked == ciphertext {
		t.Fatalf("expected enforced masked value on direct repository call, got %T %v", views[0].Output.TimeElapsed, views[0].Output.TimeElapsed)
	}
}

func TestFilmRepository_DBMSSpansOnlyRawRepository(t *testing.T) {
	raw := &fakeRawFilmRepository{
		listByTenant: func(ctx context.Context, tenantID string) ([]service.FilmRecord, error) {
			time.Sleep(5 * time.Millisecond)
			return []service.FilmRecord{
				{TenantID: tenantID, ID: "film-1", Title: "Interstellar", TimeElapsedCT: "ct"},
			}, nil
		},
	}
	policyEnforcer := fakePolicyEnforcer{
		enforceFilmRead: func(ctx context.Context, principal service.Principal, reqCtx service.RequestContext, film service.FilmReadInput) (service.FilmReadResult, error) {
			stop := perf.Span(ctx, "enforcer_ms")
			time.Sleep(25 * time.Millisecond)
			stop()
			return service.FilmReadResult{
				TimeElapsed:     120,
				FieldsDecrypted: []string{"time_elapsed"},
			}, nil
		},
	}
	bindingDeps := newTestBindingDeps(t)
	bindTestFilmRecords(t, bindingDeps, []service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: "ct"}})
	repo := NewFilmRepository(raw, policyEnforcer, testLogger(), bindingDeps)

	ctx, pctx := perf.NewContext(withAccess("admin", service.ActionFilmRead))
	_, err := repo.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}

	metrics := pctx.Metrics()
	if metrics["db_ms"] <= 0 {
		t.Fatalf("expected db_ms to be recorded, got %+v", metrics)
	}
	if metrics["enforcer_ms"] <= 0 {
		t.Fatalf("expected enforcer_ms to be recorded, got %+v", metrics)
	}
	if metrics["db_ms"] >= metrics["enforcer_ms"] {
		t.Fatalf("expected db_ms to exclude enforcement time, got db_ms=%f enforcer_ms=%f", metrics["db_ms"], metrics["enforcer_ms"])
	}
}

func newFilmPolicyEnforcer(t *testing.T, dcsMode string) service.PolicyEnforcer {
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

func withAccess(role string, action service.Action) context.Context {
	return service.WithAccessContext(context.Background(), service.AccessContext{
		Principal: service.Principal{
			TenantID: "t1",
			UserID:   "u-" + role,
			Username: role,
			Role:     role,
			Scopes:   []string{"cinema"},
		},
		Request: service.RequestContext{
			RequestID:   "req-1",
			ClientIP:    "127.0.0.1",
			Channel:     "web",
			Purpose:     "cinema_ops",
			DeviceTrust: 1.0,
			Env:         "test",
		},
		Action: action,
	})
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakePolicyEnforcer struct {
	service.PolicyEnforcer
	enforceFilmRead func(ctx context.Context, principal service.Principal, reqCtx service.RequestContext, film service.FilmReadInput) (service.FilmReadResult, error)
}

func (f fakePolicyEnforcer) EnforceFilmRead(ctx context.Context, principal service.Principal, reqCtx service.RequestContext, film service.FilmReadInput) (service.FilmReadResult, error) {
	return f.enforceFilmRead(ctx, principal, reqCtx, film)
}

type fakeRawFilmRepository struct {
	listByTenant         func(ctx context.Context, tenantID string) ([]service.FilmRecord, error)
	updateTimeCiphertext func(ctx context.Context, tenantID, filmID, ciphertext string) (service.FilmRecord, error)
	create               func(ctx context.Context, tenantID, title, timeElapsedCT string) (service.FilmRecord, error)
}

func (f *fakeRawFilmRepository) ListByTenant(ctx context.Context, tenantID string) ([]service.FilmRecord, error) {
	return f.listByTenant(ctx, tenantID)
}

func (f *fakeRawFilmRepository) UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (service.FilmRecord, error) {
	if f.updateTimeCiphertext == nil {
		return service.FilmRecord{}, errors.New("unexpected UpdateTimeCiphertext call")
	}
	return f.updateTimeCiphertext(ctx, tenantID, filmID, ciphertext)
}

func (f *fakeRawFilmRepository) Create(ctx context.Context, tenantID, title, timeElapsedCT string) (service.FilmRecord, error) {
	if f.create == nil {
		return service.FilmRecord{}, errors.New("unexpected Create call")
	}
	return f.create(ctx, tenantID, title, timeElapsedCT)
}
