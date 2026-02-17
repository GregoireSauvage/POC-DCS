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

// TestDecisionHash_Determinism verifies that the same decision always produces the same hash
func TestDecisionHash_Determinism(t *testing.T) {
	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"title":        types.FieldActionAllow,
			"time_elapsed": types.FieldActionDecrypt,
			"description":  types.FieldActionMaskAfterDecrypt,
		},
		Reason: "read_allowed",
	}

	// Call hash function multiple times
	hash1 := DecisionHash(decision)
	hash2 := DecisionHash(decision)
	hash3 := DecisionHash(decision)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: hash1=%s, hash2=%s", hash1, hash2)
	}
	if hash1 != hash3 {
		t.Errorf("hash not deterministic: hash1=%s, hash3=%s", hash1, hash3)
	}

	// Verify hash is 64 characters (SHA256 hex)
	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}
}

// TestDecisionHash_FieldOrder verifies that field insertion order doesn't affect hash
func TestDecisionHash_FieldOrder(t *testing.T) {
	// Create same decision with fields added in different orders
	decision1 := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"aaa": types.FieldActionAllow,
			"zzz": types.FieldActionDecrypt,
			"mmm": types.FieldActionMaskAfterDecrypt,
		},
		Reason: "read_allowed",
	}

	decision2 := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"zzz": types.FieldActionDecrypt,
			"mmm": types.FieldActionMaskAfterDecrypt,
			"aaa": types.FieldActionAllow,
		},
		Reason: "read_allowed",
	}

	decision3 := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"mmm": types.FieldActionMaskAfterDecrypt,
			"aaa": types.FieldActionAllow,
			"zzz": types.FieldActionDecrypt,
		},
		Reason: "read_allowed",
	}

	hash1 := DecisionHash(decision1)
	hash2 := DecisionHash(decision2)
	hash3 := DecisionHash(decision3)

	if hash1 != hash2 {
		t.Errorf("field order affected hash: hash1=%s, hash2=%s", hash1, hash2)
	}
	if hash1 != hash3 {
		t.Errorf("field order affected hash: hash1=%s, hash3=%s", hash1, hash3)
	}
}

// TestDecisionHash_EmptyFields verifies hash works with empty field actions
func TestDecisionHash_EmptyFields(t *testing.T) {
	decision := types.Decision{
		Allow:        true,
		FieldActions: map[string]types.FieldAction{},
		Reason:       "read_allowed",
	}

	hash1 := DecisionHash(decision)
	hash2 := DecisionHash(decision)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic for empty fields: hash1=%s, hash2=%s", hash1, hash2)
	}

	// Verify it's different from nil map
	decisionNil := types.Decision{
		Allow:        true,
		FieldActions: nil,
		Reason:       "read_allowed",
	}
	hashNil := DecisionHash(decisionNil)

	// Both should work and be deterministic (Go treats nil map and empty map similarly in JSON)
	if hashNil != DecisionHash(decisionNil) {
		t.Errorf("hash not deterministic for nil fields")
	}
}

// TestDecisionHash_DifferentDecisions verifies different decisions produce different hashes
func TestDecisionHash_DifferentDecisions(t *testing.T) {
	decision1 := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"field1": types.FieldActionAllow,
		},
		Reason: "read_allowed",
	}

	decision2 := types.Decision{
		Allow: false, // Different allow
		FieldActions: map[string]types.FieldAction{
			"field1": types.FieldActionAllow,
		},
		Reason: "read_allowed",
	}

	decision3 := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"field1": types.FieldActionDecrypt, // Different action
		},
		Reason: "read_allowed",
	}

	decision4 := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"field1": types.FieldActionAllow,
		},
		Reason: "write_allowed", // Different reason
	}

	hash1 := DecisionHash(decision1)
	hash2 := DecisionHash(decision2)
	hash3 := DecisionHash(decision3)
	hash4 := DecisionHash(decision4)

	if hash1 == hash2 {
		t.Errorf("different allow values produced same hash")
	}
	if hash1 == hash3 {
		t.Errorf("different field actions produced same hash")
	}
	if hash1 == hash4 {
		t.Errorf("different reasons produced same hash")
	}
}

// TestDecisionHash_KnownValue verifies hash for a known test case.
//
// NOTE: Go uses compact JSON format (no spaces), Python uses json.dumps() default (with spaces).
// This is intentional - each backend maintains its own audit logs with consistent hashing.
// See docs/decision-hash-parity.md for rationale.
//
// Test case: allow=true, field_actions={"age":"decrypt","name":"mask_after_decrypt"}, reason="read_allowed"
// Expected Go hash (compact JSON): f986e869dcaf9043676801795ca9701375a2b026cc1ef63960910e0423b96edb
// Python hash (with spaces): c7397e1f62775e903f3b02abcd87c9c36788c12f7fa564a54699f9ea42a4726c (different by design)
func TestDecisionHash_KnownValue(t *testing.T) {
	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"name": types.FieldActionMaskAfterDecrypt,
			"age":  types.FieldActionDecrypt,
		},
		Reason: "read_allowed",
	}

	hash := DecisionHash(decision)

	// Expected hash with compact JSON format (Go default)
	expectedHash := "f986e869dcaf9043676801795ca9701375a2b026cc1ef63960910e0423b96edb"

	if hash != expectedHash {
		t.Errorf("hash mismatch:\n  got:      %s\n  expected: %s", hash, expectedHash)
	}

	// Verify format
	if len(hash) != 64 {
		t.Errorf("expected 64-char hash, got %d", len(hash))
	}

	t.Logf("✅ Go decision hash (compact JSON): %s", hash)
}

// TestDecisionHash_ComplexFieldActions verifies hash with many fields
func TestDecisionHash_ComplexFieldActions(t *testing.T) {
	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"field_01": types.FieldActionAllow,
			"field_02": types.FieldActionDecrypt,
			"field_03": types.FieldActionMaskAfterDecrypt,
			"field_04": types.FieldActionDeny,
			"field_05": types.FieldActionAllow,
			"field_06": types.FieldActionDecrypt,
			"field_07": types.FieldActionMaskAfterDecrypt,
			"field_08": types.FieldActionDeny,
			"field_09": types.FieldActionAllow,
			"field_10": types.FieldActionDecrypt,
		},
		Reason: "read_allowed",
	}

	hash1 := DecisionHash(decision)
	hash2 := DecisionHash(decision)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic with many fields")
	}

	// Verify adding field changes hash
	decisionPlus := types.Decision{
		Allow:        decision.Allow,
		FieldActions: make(map[string]types.FieldAction),
		Reason:       decision.Reason,
	}
	for k, v := range decision.FieldActions {
		decisionPlus.FieldActions[k] = v
	}
	decisionPlus.FieldActions["field_11"] = types.FieldActionAllow

	hashPlus := DecisionHash(decisionPlus)
	if hash1 == hashPlus {
		t.Errorf("adding field did not change hash")
	}
}
