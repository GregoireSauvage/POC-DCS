package runtime

import "testing"

func TestSettings_DcsMode(t *testing.T) {
	rt := New("on", 1)
	if !rt.DcsEnabled() {
		t.Fatalf("expected DCS enabled by default")
	}

	off := "off"
	rt.Set(&off, nil)
	if rt.DcsEnabled() {
		t.Fatalf("expected DCS disabled after off override")
	}

	zero := "0"
	rt.Set(&zero, nil)
	if rt.DcsEnabled() {
		t.Fatalf("expected DCS disabled after zero override")
	}
}

func TestSettings_CacheLevel(t *testing.T) {
	rt := New("on", 1)
	if rt.CacheLevel() != 1 {
		t.Fatalf("expected cache level 1, got %d", rt.CacheLevel())
	}

	lvl := 3
	rt.Set(nil, &lvl)
	if rt.CacheLevel() != 3 {
		t.Fatalf("expected cache level 3, got %d", rt.CacheLevel())
	}

	neg := -10
	rt.Set(nil, &neg)
	if rt.CacheLevel() != 0 {
		t.Fatalf("expected cache level clamped to 0, got %d", rt.CacheLevel())
	}
}
