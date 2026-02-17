package pip

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type errorClassificationStore struct{}

func (e *errorClassificationStore) GetByResourceType(_ context.Context, _ string) (map[string]types.Classification, error) {
	return nil, errors.New("store error")
}

func TestProvider_DefaultContextValues(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	store := &fakeClassificationStore{
		data: map[string]types.Classification{
			"title":        types.ClassificationPublic,
			"time_elapsed": types.ClassificationSensitive,
		},
	}

	p := NewProvider(rt, cm, store, Config{
		Env:            "dev",
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.9,
		ClientIPHeader: "x-real-ip",
	})

	reqCtx := types.RequestContext{RequestID: "r1", ClientIP: "127.0.0.1"}
	pi, err := p.Build(context.Background(), Input{
		Principal:    types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      reqCtx,
		CryptoMeta: map[string]map[string]string{
			"time_elapsed": {"ciphertext_field": "time_elapsed_ct"},
			"ghost":        {"ciphertext_field": "ghost_ct"},
		},
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if pi.Context.Channel != "web" {
		t.Fatalf("expected default channel, got %q", pi.Context.Channel)
	}
	if pi.Context.Purpose != "cinema_ops" {
		t.Fatalf("expected default purpose, got %q", pi.Context.Purpose)
	}
	if pi.Context.Env != "dev" {
		t.Fatalf("expected default env, got %q", pi.Context.Env)
	}
	if pi.Context.DeviceTrust != 0.9 {
		t.Fatalf("expected default device trust, got %v", pi.Context.DeviceTrust)
	}

	timeMeta, ok := pi.Resource.Fields["time_elapsed"]
	if !ok {
		t.Fatalf("expected time_elapsed field in policy input")
	}
	if timeMeta.Crypto["ciphertext_field"] != "time_elapsed_ct" {
		t.Fatalf("expected crypto meta for time_elapsed to be set")
	}
	if _, ok := pi.Resource.Fields["ghost"]; ok {
		t.Fatalf("unexpected ghost field in policy input")
	}
}

func TestProvider_PreservesProvidedContext(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	store := &fakeClassificationStore{data: map[string]types.Classification{"title": types.ClassificationPublic}}
	p := NewProvider(rt, cm, store, Config{
		Env:            "dev",
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})

	reqCtx := types.RequestContext{
		RequestID:   "r1",
		ClientIP:    "127.0.0.1",
		Channel:     "mobile",
		Purpose:     "testing",
		Env:         "staging",
		DeviceTrust: 0.2,
	}
	pi, err := p.Build(context.Background(), Input{
		Principal:    types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      reqCtx,
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if pi.Context.Channel != "mobile" || pi.Context.Purpose != "testing" || pi.Context.Env != "staging" {
		t.Fatalf("expected provided context to be preserved")
	}
	if pi.Context.DeviceTrust != 0.2 {
		t.Fatalf("expected provided device trust to be preserved")
	}
}

func TestProvider_ClassificationStoreError(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	p := NewProvider(rt, cm, &errorClassificationStore{}, Config{
		Env:            "dev",
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})

	_, err := p.Build(context.Background(), Input{
		Principal:    types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      types.RequestContext{RequestID: "r1"},
	})
	if err == nil {
		t.Fatalf("expected error when classification store fails")
	}
}

func TestProvider_NoCacheAtLevel0(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	store := &fakeClassificationStore{data: map[string]types.Classification{"title": types.ClassificationPublic}}
	p := NewProvider(rt, cm, store, Config{
		Env:            "dev",
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})

	reqCtx := types.RequestContext{RequestID: "r1"}
	_, _ = p.Build(context.Background(), Input{
		Principal:    types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      reqCtx,
	})
	_, _ = p.Build(context.Background(), Input{
		Principal:    types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      reqCtx,
	})

	if store.calls != 2 {
		t.Fatalf("expected store to be called twice at cache level 0, got %d", store.calls)
	}
}

