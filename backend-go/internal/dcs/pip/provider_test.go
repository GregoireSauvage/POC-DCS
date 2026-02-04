package pip

import (
	"context"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type fakeClassificationStore struct {
	calls int
	data  map[string]types.Classification
}

func (f *fakeClassificationStore) GetByResourceType(_ context.Context, _ string) (map[string]types.Classification, error) {
	f.calls++
	out := make(map[string]types.Classification, len(f.data))
	for k, v := range f.data {
		out[k] = v
	}
	return out, nil
}

func TestProvider_UsesClassificationCacheAtLevel1(t *testing.T) {
	rt := runtime.New("on", 1)
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
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})

	principal := types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := types.RequestContext{RequestID: "r1", ClientIP: "127.0.0.1"}

	_, err := p.Build(context.Background(), Input{
		Principal:    principal,
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      reqCtx,
		CryptoMeta: map[string]map[string]string{
			"time_elapsed": {"ciphertext_field": "time_elapsed_ct"},
		},
	})
	if err != nil {
		t.Fatalf("build policy input failed: %v", err)
	}
	_, err = p.Build(context.Background(), Input{
		Principal:    principal,
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      reqCtx,
	})
	if err != nil {
		t.Fatalf("build policy input failed on second call: %v", err)
	}

	if store.calls != 1 {
		t.Fatalf("expected 1 store call with cache, got %d", store.calls)
	}
}

func TestProvider_SkipsClassificationWhenDcsOff(t *testing.T) {
	rt := runtime.New("off", 3)
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

	principal := types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"}
	reqCtx := types.RequestContext{RequestID: "r1", ClientIP: "127.0.0.1"}

	pi, err := p.Build(context.Background(), Input{
		Principal:    principal,
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		Request:      reqCtx,
	})
	if err != nil {
		t.Fatalf("build policy input failed: %v", err)
	}

	if len(pi.Resource.Fields) != 0 {
		t.Fatalf("expected no fields in DCS off mode")
	}
	if store.calls != 0 {
		t.Fatalf("expected classification store not called in DCS off mode")
	}
}
