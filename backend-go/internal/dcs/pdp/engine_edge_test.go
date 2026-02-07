package pdp

import (
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func newEngineForTest(mode string, cacheLevel int) *Engine {
	rt := runtime.New(mode, cacheLevel)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})
	return NewEngine(rt, cm)
}

func TestEngine_TenantMismatch(t *testing.T) {
	engine := newEngineForTest("on", 0)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:    "film.read",
		Resource: types.Resource{
			Type:     "film",
			ID:       "f1",
			TenantID: "t2",
			Fields: map[string]types.FieldMeta{
				"title": {Classification: types.ClassificationPublic},
			},
		},
	}

	decision, _ := engine.Evaluate(input)
	if decision.Allow {
		t.Fatalf("expected deny for tenant mismatch")
	}
	if decision.Reason != "tenant_mismatch" {
		t.Fatalf("expected tenant_mismatch, got %q", decision.Reason)
	}
}

func TestEngine_UnknownAction(t *testing.T) {
	engine := newEngineForTest("on", 0)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:    "unknown.action",
		Resource:  types.Resource{Type: "film", ID: "f1", TenantID: "t1"},
	}

	decision, _ := engine.Evaluate(input)
	if decision.Allow {
		t.Fatalf("expected deny for unknown action")
	}
	if decision.Reason != "unknown_action" {
		t.Fatalf("expected unknown_action, got %q", decision.Reason)
	}
}

func TestEngine_SpectatorAgentHardening(t *testing.T) {
	engine := newEngineForTest("on", 0)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "agent", Role: "agent"},
		Action:    "spectator.read",
		Resource: types.Resource{
			Type:     "spectator",
			ID:       "s1",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"name":        {Classification: types.ClassificationPublic},
				"external_id": {Classification: types.ClassificationPublic},
				"age":         {Classification: types.ClassificationSensitive},
			},
		},
	}

	decision, _ := engine.Evaluate(input)
	if !decision.Allow {
		t.Fatalf("expected allow for agent read")
	}
	if decision.FieldActions["name"] != types.FieldActionMaskAfterDecrypt {
		t.Fatalf("expected name to be masked for agent spectator hardening")
	}
	if decision.FieldActions["external_id"] != types.FieldActionMaskAfterDecrypt {
		t.Fatalf("expected external_id to be masked for agent spectator hardening")
	}
	if decision.FieldActions["age"] != types.FieldActionDecrypt {
		t.Fatalf("expected age to remain decrypt for agent")
	}
}

func TestEngine_CacheNotUsedForNonFilmActions(t *testing.T) {
	engine := newEngineForTest("on", 3)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:    "hall.read",
		Resource: types.Resource{
			Type:     "hall",
			ID:       "h1",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"name": {Classification: types.ClassificationPublic},
			},
		},
	}

	_, hit1 := engine.Evaluate(input)
	_, hit2 := engine.Evaluate(input)
	if hit1 || hit2 {
		t.Fatalf("expected no cache hits for non-film actions")
	}
}

func TestDecisionCacheKey_OrderIndependence(t *testing.T) {
	input1 := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:    "film.read",
		Resource: types.Resource{
			Type:     "film",
			ID:       "f1",
			OwnerID:  "o1",
			TenantID: "t1",
			Labels:   []string{"b", "a"},
			Fields: map[string]types.FieldMeta{
				"time_elapsed": {Classification: types.ClassificationSensitive},
				"title":        {Classification: types.ClassificationPublic},
			},
		},
	}

	input2 := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:    "film.read",
		Resource: types.Resource{
			Type:     "film",
			ID:       "f1",
			OwnerID:  "o1",
			TenantID: "t1",
			Labels:   []string{"a", "b"},
			Fields: map[string]types.FieldMeta{
				"title":        {Classification: types.ClassificationPublic},
				"time_elapsed": {Classification: types.ClassificationSensitive},
			},
		},
	}

	key1 := decisionCacheKey(true, input1)
	key2 := decisionCacheKey(true, input2)
	if key1 != key2 {
		t.Fatalf("expected cache key to be order-independent")
	}
}

