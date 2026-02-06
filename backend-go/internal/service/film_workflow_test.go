package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pdp"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type fakeFilmRepo struct {
	films []FilmRecord
}

func (f *fakeFilmRepo) ListByTenant(_ context.Context, tenantID string) ([]FilmRecord, error) {
	out := make([]FilmRecord, 0, len(f.films))
	for _, film := range f.films {
		if film.TenantID == tenantID {
			out = append(out, film)
		}
	}
	return out, nil
}

func (f *fakeFilmRepo) UpdateTimeCiphertext(_ context.Context, tenantID, filmID, ciphertext string) (FilmRecord, error) {
	for i := range f.films {
		if f.films[i].TenantID == tenantID && f.films[i].ID == filmID {
			f.films[i].TimeElapsedCT = ciphertext
			return f.films[i], nil
		}
	}
	return FilmRecord{}, errors.New("not found")
}

type fakeKMS struct {
	encryptValue string
	decryptValue string
	encryptCalls int
	decryptCalls int
}

func (f *fakeKMS) Encrypt(_ context.Context, _ string) (string, error) {
	f.encryptCalls++
	return f.encryptValue, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, _ string) (string, error) {
	f.decryptCalls++
	return f.decryptValue, nil
}

type fakeClassifications struct {
	data map[string]types.Classification
}

func (f *fakeClassifications) GetByResourceType(_ context.Context, _ string) (map[string]types.Classification, error) {
	out := make(map[string]types.Classification, len(f.data))
	for k, v := range f.data {
		out[k] = v
	}
	return out, nil
}

func buildFilmServiceForTest(rt *runtime.Settings, repo FilmRepository, kms KMS) *FilmService {
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})
	classStore := &fakeClassifications{
		data: map[string]types.Classification{
			"title":        types.ClassificationPublic,
			"time_elapsed": types.ClassificationSensitive,
		},
	}
	provider := pip.NewProvider(rt, cm, classStore, pip.Config{
		Env:            "dev",
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})
	engine := pdp.NewEngine(rt, cm)
	applier := pep.NewFilmApplier(rt, kms)
	return NewFilmService(repo, provider, engine, applier, kms, nil) // audit service not needed for tests
}

func TestFilmService_List_DeveloperGetsMaskedValue(t *testing.T) {
	rt := runtime.New("on", 2)
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kms := &fakeKMS{decryptValue: "120"}
	svc := buildFilmServiceForTest(rt, repo, kms)

	principal := types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := types.RequestContext{RequestID: "r1", ClientIP: "127.0.0.1"}

	films, perf, err := svc.List(context.Background(), principal, reqCtx)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(films) != 1 {
		t.Fatalf("expected one film")
	}
	if films[0].TimeElapsed != "1***" {
		t.Fatalf("expected masked time_elapsed, got %#v", films[0].TimeElapsed)
	}
	if kms.decryptCalls != 1 {
		t.Fatalf("expected one decrypt call, got %d", kms.decryptCalls)
	}
	if perf.Metrics()["pdp_ms"] <= 0 {
		t.Fatalf("expected pdp_ms metric to be recorded")
	}
}

func TestFilmService_UpdateTime_DeveloperForbidden(t *testing.T) {
	rt := runtime.New("on", 2)
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:new", decryptValue: "240"}
	svc := buildFilmServiceForTest(rt, repo, kms)

	principal := types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := types.RequestContext{RequestID: "r2", ClientIP: "127.0.0.1"}

	_, _, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden error, got %v", err)
	}
	if kms.encryptCalls != 0 {
		t.Fatalf("encrypt should not be called when forbidden")
	}
}

func TestFilmService_UpdateTime_AdminAllowed(t *testing.T) {
	rt := runtime.New("on", 2)
	repo := &fakeFilmRepo{
		films: []FilmRecord{{TenantID: "t1", ID: "f1", Title: "Interstellar", TimeElapsedCT: "vault:v1:abc"}},
	}
	kms := &fakeKMS{encryptValue: "vault:v1:new", decryptValue: "240"}
	svc := buildFilmServiceForTest(rt, repo, kms)

	principal := types.Principal{TenantID: "t1", UserID: "u9", Username: "admin", Role: "admin"}
	reqCtx := types.RequestContext{RequestID: "r3", ClientIP: "127.0.0.1"}

	film, perf, err := svc.UpdateTime(context.Background(), principal, reqCtx, "f1", 240)
	if err != nil {
		t.Fatalf("update time failed: %v", err)
	}
	if film.TimeElapsed != 240 {
		t.Fatalf("expected decrypted int 240, got %#v", film.TimeElapsed)
	}
	if kms.encryptCalls != 1 || kms.decryptCalls != 1 {
		t.Fatalf("expected one encrypt and one decrypt call, got encrypt=%d decrypt=%d", kms.encryptCalls, kms.decryptCalls)
	}
	if perf.Metrics()["kms_ms"] <= 0 {
		t.Fatalf("expected kms_ms metric to be recorded")
	}
}
