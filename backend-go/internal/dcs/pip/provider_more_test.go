package pip

import (
	"context"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func TestProvider_Build_MapsResourceMetadata(t *testing.T) {
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
			"title": types.ClassificationPublic,
		},
	}
	p := NewProvider(rt, cm, store, Config{
		Env:         "dev",
		Channel:     "web",
		Purpose:     "cinema_ops",
		DeviceTrust: 0.8,
	})

	pi, err := p.Build(context.Background(), Input{
		Principal:    types.Principal{TenantID: "t42", UserID: "u1", Role: "developer"},
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   "f1",
		OwnerID:      "owner-1",
		Labels:       []string{"l1", "l2"},
		Request:      types.RequestContext{RequestID: "r1", ClientIP: "127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	if pi.Resource.ID != "f1" || pi.Resource.Type != "film" || pi.Resource.OwnerID != "owner-1" {
		t.Fatalf("resource metadata mapping failed: %+v", pi.Resource)
	}
	if pi.Resource.TenantID != "t42" {
		t.Fatalf("expected tenant from principal, got %q", pi.Resource.TenantID)
	}
	if len(pi.Resource.Labels) != 2 {
		t.Fatalf("expected labels to be mapped")
	}
}

func TestProvider_GetClassificationMap_Level1CacheHit(t *testing.T) {
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
			"title": types.ClassificationPublic,
		},
	}
	p := NewProvider(rt, cm, store, Config{})

	seed := map[string]types.Classification{
		"title": types.ClassificationSensitive,
	}
	cm.Classification.Set("film", seed, time.Minute)

	got, err := p.getClassificationMap(context.Background(), "film")
	if err != nil {
		t.Fatalf("getClassificationMap failed: %v", err)
	}
	if got["title"] != types.ClassificationSensitive {
		t.Fatalf("expected cached classification value, got %q", got["title"])
	}
	if store.calls != 0 {
		t.Fatalf("expected no store call on cache hit, got %d", store.calls)
	}
}

func TestProvider_GetClassificationMap_CacheStoresOnMiss(t *testing.T) {
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
			"title": types.ClassificationPublic,
		},
	}
	p := NewProvider(rt, cm, store, Config{})

	_, err := p.getClassificationMap(context.Background(), "film")
	if err != nil {
		t.Fatalf("getClassificationMap failed: %v", err)
	}
	if _, found := cm.Classification.Get("film"); !found {
		t.Fatalf("expected classification to be written to cache on miss")
	}
}
