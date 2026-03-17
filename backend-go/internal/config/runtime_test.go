package config

import "testing"

func TestDCSRuntime_DcsEnabled(t *testing.T) {
	rt := NewDCSRuntime("off", 2)
	if rt.DcsEnabled() {
		t.Fatalf("expected runtime to be disabled")
	}
	mode := "on"
	level := 3
	rt.Set(&mode, &level)
	if !rt.DcsEnabled() {
		t.Fatalf("expected runtime to be enabled after Set")
	}
	if rt.CacheLevel() != 3 {
		t.Fatalf("expected cache level 3, got %d", rt.CacheLevel())
	}
}
