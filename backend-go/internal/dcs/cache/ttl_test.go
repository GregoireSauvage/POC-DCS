package cache

import (
	"testing"
	"time"
)

func TestTTL_GetSet(t *testing.T) {
	cache := NewTTL[string, string](10, 1*time.Second)

	// Set a value
	cache.Set("key1", "value1", 0)

	// Get the value
	val, found := cache.Get("key1")
	if !found {
		t.Error("Expected to find key1")
	}
	if val != "value1" {
		t.Errorf("Expected value1, got %s", val)
	}
}

func TestTTL_GetNotFound(t *testing.T) {
	cache := NewTTL[string, string](10, 1*time.Second)

	_, found := cache.Get("nonexistent")
	if found {
		t.Error("Expected not to find nonexistent key")
	}
}

func TestTTL_Expiration(t *testing.T) {
	cache := NewTTL[string, string](10, 100*time.Millisecond)

	cache.Set("key1", "value1", 100*time.Millisecond)

	// Should be present immediately
	_, found := cache.Get("key1")
	if !found {
		t.Error("Expected to find key1 immediately after set")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, found = cache.Get("key1")
	if found {
		t.Error("Expected key1 to be expired")
	}
}

func TestTTL_MaxEntries(t *testing.T) {
	cache := NewTTL[string, string](3, 1*time.Second)

	// Fill cache to max
	cache.Set("key1", "value1", 0)
	cache.Set("key2", "value2", 0)
	cache.Set("key3", "value3", 0)

	// Add one more - should evict one entry
	cache.Set("key4", "value4", 0)

	// At least one of the first three should be evicted
	count := 0
	if _, found := cache.Get("key1"); found {
		count++
	}
	if _, found := cache.Get("key2"); found {
		count++
	}
	if _, found := cache.Get("key3"); found {
		count++
	}
	if _, found := cache.Get("key4"); found {
		count++
	}

	if count != 3 {
		t.Errorf("Expected 3 entries in cache, got %d", count)
	}
}

func TestTTL_Clear(t *testing.T) {
	cache := NewTTL[string, string](10, 1*time.Second)

	cache.Set("key1", "value1", 0)
	cache.Set("key2", "value2", 0)

	cache.Clear()

	_, found1 := cache.Get("key1")
	_, found2 := cache.Get("key2")

	if found1 || found2 {
		t.Error("Expected cache to be empty after Clear()")
	}
}

func TestTTL_CustomTTL(t *testing.T) {
	cache := NewTTL[string, string](10, 1*time.Second)

	// Set with custom TTL
	cache.Set("key1", "value1", 50*time.Millisecond)

	// Should be present immediately
	_, found := cache.Get("key1")
	if !found {
		t.Error("Expected to find key1 immediately")
	}

	// Wait for custom TTL expiration
	time.Sleep(60 * time.Millisecond)

	_, found = cache.Get("key1")
	if found {
		t.Error("Expected key1 to expire after custom TTL")
	}
}

func TestTTL_ZeroTTLUsesDefault(t *testing.T) {
	defaultTTL := 100 * time.Millisecond
	cache := NewTTL[string, string](10, defaultTTL)

	// Set with zero TTL (should use default)
	cache.Set("key1", "value1", 0)

	// Should be present immediately
	_, found := cache.Get("key1")
	if !found {
		t.Error("Expected to find key1")
	}

	// Wait for default TTL
	time.Sleep(120 * time.Millisecond)

	_, found = cache.Get("key1")
	if found {
		t.Error("Expected key1 to expire after default TTL")
	}
}
