package pdp

import (
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func TestEngine_DcsOn_FieldActions(t *testing.T) {
	rt := runtime.New("on", 2)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})
	engine := NewEngine(rt, cm)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "admin", Role: "admin"},
		Action:    "film.read",
		Resource: types.Resource{
			Type:     "film",
			ID:       "f1",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"title":        {Classification: types.ClassificationPublic},
				"time_elapsed": {Classification: types.ClassificationSensitive},
			},
		},
	}

	decision, _ := engine.Evaluate(input)
	if !decision.Allow {
		t.Fatalf("expected allow for admin read")
	}
	if decision.FieldActions["time_elapsed"] != types.FieldActionDecrypt {
		t.Fatalf("expected decrypt on sensitive field for admin")
	}
}

func TestEngine_CacheAtLevel2(t *testing.T) {
	rt := runtime.New("on", 2)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})
	engine := NewEngine(rt, cm)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:    "film.read",
		Resource: types.Resource{
			Type:     "film",
			ID:       "f1",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"title":        {Classification: types.ClassificationPublic},
				"time_elapsed": {Classification: types.ClassificationSensitive},
			},
		},
	}

	_, hit1 := engine.Evaluate(input)
	_, hit2 := engine.Evaluate(input)
	if hit1 {
		t.Fatalf("first call should not be cache hit")
	}
	if !hit2 {
		t.Fatalf("second call should be cache hit")
	}
}

func TestEngine_DcsOff(t *testing.T) {
	rt := runtime.New("off", 3)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})
	engine := NewEngine(rt, cm)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Username: "dev", Role: "developer"},
		Action:    "film.read",
		Resource:  types.Resource{Type: "film", ID: "f1", TenantID: "t1"},
	}

	decision, _ := engine.Evaluate(input)
	if !decision.Allow {
		t.Fatalf("expected read allow in dcs off mode")
	}
	if len(decision.FieldActions) != 0 {
		t.Fatalf("expected no field actions in dcs off mode")
	}
	if decision.Reason != "dcs_off" {
		t.Fatalf("expected dcs_off reason, got %q", decision.Reason)
	}
}
