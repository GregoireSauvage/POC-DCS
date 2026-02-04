package cache

import (
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
)

func TestTTLCache_Expires(t *testing.T) {
	c := NewTTL[string, string](10, 20*time.Millisecond)
	c.Set("k1", "v1", 0)

	if v, ok := c.Get("k1"); !ok || v != "v1" {
		t.Fatalf("expected cache hit before expiry")
	}

	time.Sleep(30 * time.Millisecond)
	if _, ok := c.Get("k1"); ok {
		t.Fatalf("expected cache miss after expiry")
	}
}

func TestManager_LevelEnabled(t *testing.T) {
	rt := runtime.New("on", 1)
	m := NewManager(rt, Options{
		MaxEntries:        100,
		ClassificationTTL: 5 * time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            10 * time.Second,
		PepperTTL:         5 * time.Minute,
	})

	if !m.LevelEnabled(1) {
		t.Fatalf("level 1 should be enabled")
	}
	if m.LevelEnabled(2) {
		t.Fatalf("level 2 should not be enabled")
	}

	level := 3
	rt.Set(nil, &level)
	if !m.LevelEnabled(3) {
		t.Fatalf("level 3 should be enabled after runtime update")
	}
}
