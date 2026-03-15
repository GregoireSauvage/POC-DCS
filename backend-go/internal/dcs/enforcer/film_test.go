package enforcer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	dcsconfig "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	serviceauth "github.com/neoweyss/poc-dcs/backend-go/internal/service/authorization"
)

type fixedClassificationStore struct {
	data map[string]types.Classification
	err  error
}

func (f *fixedClassificationStore) GetByResourceType(_ context.Context, _ string) (map[string]types.Classification, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]types.Classification, len(f.data))
	for k, v := range f.data {
		out[k] = v
	}
	return out, nil
}

type fakeCryptoService struct {
	value string
	err   error
}

func (f *fakeCryptoService) Encrypt(_ context.Context, plaintext string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "vault:v1:encrypted-" + plaintext, nil
}

func (f *fakeCryptoService) Decrypt(_ context.Context, _ string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.value, nil
}

func (f *fakeCryptoService) GetPepper(_ context.Context, _ string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []byte("test-pepper"), nil
}

func newDcsEnforcerForTest(mode string, cacheLevel int, store pip.ClassificationStore, crypto CryptoService) *DcsEnforcer {
	rt := runtime.New(mode, cacheLevel)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})
	provider := pip.NewProvider(rt, cm, store, pip.Config{
		Env:            "dev",
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})
	cfg := dcsconfig.Defaults()
	policy := dcsconfig.NewPDPPolicy(&cfg.PDP)
	pdpAuthorizer := serviceauth.NewPDP(policy)
	baseAuthorizer := serviceauth.NewAuthorizer(rt, pdpAuthorizer)
	filmApplier := pep.NewFilmApplier(rt, crypto)
	spectatorApplier := pep.NewSpectatorApplier(crypto)
	return New(provider, baseAuthorizer, filmApplier, spectatorApplier, crypto, "secret/dcs")
}

func defaultFilmStore() pip.ClassificationStore {
	return &fixedClassificationStore{
		data: map[string]types.Classification{
			"title":        types.ClassificationPublic,
			"time_elapsed": types.ClassificationSensitive,
		},
	}
}

func defaultPrincipal(role string) service.Principal {
	return service.Principal{
		TenantID: "t1",
		UserID:   "u1",
		Username: role,
		Role:     role,
	}
}

func defaultReqCtx() service.RequestContext {
	return service.RequestContext{
		RequestID:   "r1",
		ClientIP:    "127.0.0.1",
		Channel:     "web",
		Purpose:     "cinema_ops",
		DeviceTrust: 0.8,
		Env:         "dev",
	}
}

func TestDcsEnforcer_EvaluateFilmUpdateTime_AdminAllowed(t *testing.T) {
	e := newDcsEnforcerForTest("on", 2, defaultFilmStore(), &fakeCryptoService{value: "120"})

	decision, err := e.EvaluateFilmUpdateTime(context.Background(), defaultPrincipal("admin"), defaultReqCtx(), "f1")
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if !decision.Allow {
		t.Fatalf("expected admin to be allowed")
	}
	if decision.Reason != "write_allowed" {
		t.Fatalf("unexpected reason: %q", decision.Reason)
	}
}

func TestDcsEnforcer_EvaluateFilmUpdateTime_DeveloperForbidden(t *testing.T) {
	e := newDcsEnforcerForTest("on", 2, defaultFilmStore(), &fakeCryptoService{value: "120"})

	decision, err := e.EvaluateFilmUpdateTime(context.Background(), defaultPrincipal("developer"), defaultReqCtx(), "f1")
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if decision.Allow {
		t.Fatalf("expected developer to be forbidden")
	}
	if decision.Reason != "write_forbidden" {
		t.Fatalf("unexpected reason: %q", decision.Reason)
	}
}

func TestDcsEnforcer_EnforceFilmRead_DeveloperMasked(t *testing.T) {
	e := newDcsEnforcerForTest("on", 2, defaultFilmStore(), &fakeCryptoService{value: "120"})

	result, err := e.EnforceFilmRead(context.Background(), defaultPrincipal("developer"), defaultReqCtx(), service.FilmReadInput{
		FilmID:        "f1",
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("enforce read failed: %v", err)
	}
	if result.TimeElapsed != "1***" {
		t.Fatalf("expected masked time_elapsed, got %#v", result.TimeElapsed)
	}
}

func TestDcsEnforcer_EnforceFilmRead_AdminDecrypt(t *testing.T) {
	e := newDcsEnforcerForTest("on", 2, defaultFilmStore(), &fakeCryptoService{value: "240"})

	result, err := e.EnforceFilmRead(context.Background(), defaultPrincipal("admin"), defaultReqCtx(), service.FilmReadInput{
		FilmID:        "f1",
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("enforce read failed: %v", err)
	}
	if result.TimeElapsed != 240 {
		t.Fatalf("expected decrypted int 240, got %#v", result.TimeElapsed)
	}
}

func TestDcsEnforcer_EnforceFilmRead_PIPError(t *testing.T) {
	storeErr := errors.New("classification store down")
	e := newDcsEnforcerForTest("on", 2, &fixedClassificationStore{err: storeErr}, &fakeCryptoService{value: "240"})

	_, err := e.EnforceFilmRead(context.Background(), defaultPrincipal("admin"), defaultReqCtx(), service.FilmReadInput{
		FilmID:        "f1",
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if !errors.Is(err, storeErr) {
		t.Fatalf("expected store error, got %v", err)
	}
}

func TestDcsEnforcer_EvaluateFilmUpdateTime_DCSOff(t *testing.T) {
	e := newDcsEnforcerForTest("off", 0, defaultFilmStore(), &fakeCryptoService{value: "120"})

	decision, err := e.EvaluateFilmUpdateTime(context.Background(), defaultPrincipal("developer"), defaultReqCtx(), "f1")
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if decision.Allow {
		t.Fatalf("expected developer write to be denied in dcs off mode")
	}
	if decision.Reason != "dcs_off" {
		t.Fatalf("expected dcs_off reason, got %q", decision.Reason)
	}
}
