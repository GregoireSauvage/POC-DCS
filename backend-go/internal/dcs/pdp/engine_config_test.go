package pdp

import (
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	dcsconfig "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

// TestEngine_ConfigDrivenActions verifies that PDP uses config action lists
func TestEngine_ConfigDrivenActions(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	// Custom config with different action lists
	cfg := &dcsconfig.PDPConfig{
		DefaultClassification: types.ClassificationInternal,
		ReadActions:           []string{"custom.read"},
		WriteActions:          []string{"custom.write"},
		BootstrapActions:      []string{"custom.bootstrap"},
		AuditActions:          []string{"custom.audit"},
		RoleClassificationActions: map[string]map[string]string{
			"admin": {
				"PUBLIC": "allow",
			},
		},
		SpectatorAgentHardeningFields: []string{},
	}

	engine := NewEngine(rt, cm, cfg)

	// Test read action (should allow)
	readInput := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "developer"},
		Action:    "custom.read",
		Resource:  types.Resource{Type: "test", TenantID: "t1", Fields: map[string]types.FieldMeta{}},
	}
	decision, _ := engine.Evaluate(readInput)
	if !decision.Allow {
		t.Errorf("Expected custom.read to be allowed (in ReadActions), got deny")
	}
	if decision.Reason != "read_allowed" {
		t.Errorf("Expected reason 'read_allowed', got %q", decision.Reason)
	}

	// Test write action (should deny for developer, allow for admin)
	writeInputDev := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "developer"},
		Action:    "custom.write",
		Resource:  types.Resource{Type: "test", TenantID: "t1", Fields: map[string]types.FieldMeta{}},
	}
	decision, _ = engine.Evaluate(writeInputDev)
	if decision.Allow {
		t.Errorf("Expected custom.write to be denied for developer")
	}
	if decision.Reason != "write_forbidden" {
		t.Errorf("Expected reason 'write_forbidden', got %q", decision.Reason)
	}

	writeInputAdmin := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "admin"},
		Action:    "custom.write",
		Resource:  types.Resource{Type: "test", TenantID: "t1", Fields: map[string]types.FieldMeta{}},
	}
	decision, _ = engine.Evaluate(writeInputAdmin)
	if !decision.Allow {
		t.Errorf("Expected custom.write to be allowed for admin")
	}
	if decision.Reason != "write_allowed" {
		t.Errorf("Expected reason 'write_allowed', got %q", decision.Reason)
	}

	// Test audit action (should be admin-only)
	auditInputAgent := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "agent"},
		Action:    "custom.audit",
		Resource:  types.Resource{Type: "test", TenantID: "t1", Fields: map[string]types.FieldMeta{}},
	}
	decision, _ = engine.Evaluate(auditInputAgent)
	if decision.Allow {
		t.Errorf("Expected custom.audit to be denied for agent")
	}
	if decision.Reason != "audit_admin_only" {
		t.Errorf("Expected reason 'audit_admin_only', got %q", decision.Reason)
	}

	// Test bootstrap action (should allow for admin)
	bootstrapInput := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "admin"},
		Action:    "custom.bootstrap",
		Resource:  types.Resource{Type: "test", TenantID: "t1", Fields: map[string]types.FieldMeta{}},
	}
	decision, _ = engine.Evaluate(bootstrapInput)
	if !decision.Allow {
		t.Errorf("Expected custom.bootstrap to be allowed for admin")
	}
	if decision.Reason != "bootstrap_allowed" {
		t.Errorf("Expected reason 'bootstrap_allowed', got %q", decision.Reason)
	}

	// Test unknown action (should deny)
	unknownInput := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "admin"},
		Action:    "unknown.action",
		Resource:  types.Resource{Type: "test", TenantID: "t1", Fields: map[string]types.FieldMeta{}},
	}
	decision, _ = engine.Evaluate(unknownInput)
	if decision.Allow {
		t.Errorf("Expected unknown.action to be denied")
	}
	if decision.Reason != "unknown_action" {
		t.Errorf("Expected reason 'unknown_action', got %q", decision.Reason)
	}
}

// TestEngine_DefaultClassification verifies that missing classifications use default
func TestEngine_DefaultClassification(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	cfg := &dcsconfig.PDPConfig{
		DefaultClassification: types.ClassificationSensitive,
		ReadActions:           []string{"test.read"},
		WriteActions:          []string{},
		BootstrapActions:      []string{},
		AuditActions:          []string{},
		RoleClassificationActions: map[string]map[string]string{
			"agent": {
				"PUBLIC":    "allow",
				"SENSITIVE": "decrypt",
			},
		},
		SpectatorAgentHardeningFields: []string{},
	}

	engine := NewEngine(rt, cm, cfg)

	// Field with no classification should use default (SENSITIVE)
	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "agent"},
		Action:    "test.read",
		Resource: types.Resource{
			Type:     "test",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"field1": {Classification: types.ClassificationPublic},
				"field2": {Classification: ""},    // Empty - should use default
				"field3": {Classification: ""},    // Empty - should use default
			},
		},
	}

	decision, _ := engine.Evaluate(input)
	if !decision.Allow {
		t.Fatalf("Expected allow for read action")
	}

	if decision.FieldActions["field1"] != types.FieldActionAllow {
		t.Errorf("Expected field1 (PUBLIC) to be allow, got %s", decision.FieldActions["field1"])
	}

	// field2 and field3 have empty classification, should use default (SENSITIVE -> decrypt)
	if decision.FieldActions["field2"] != types.FieldActionDecrypt {
		t.Errorf("Expected field2 (default SENSITIVE) to be decrypt, got %s", decision.FieldActions["field2"])
	}
	if decision.FieldActions["field3"] != types.FieldActionDecrypt {
		t.Errorf("Expected field3 (default SENSITIVE) to be decrypt, got %s", decision.FieldActions["field3"])
	}
}

// TestEngine_SpectatorHardeningFromConfig verifies config-driven hardening fields
func TestEngine_SpectatorHardeningFromConfig(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	// Custom hardening fields (different from default)
	cfg := &dcsconfig.PDPConfig{
		DefaultClassification: types.ClassificationInternal,
		ReadActions:           []string{"spectator.read"},
		WriteActions:          []string{},
		BootstrapActions:      []string{},
		AuditActions:          []string{},
		RoleClassificationActions: map[string]map[string]string{
			"agent": {
				"PUBLIC": "allow",
				"PII":    "decrypt",
			},
		},
		SpectatorAgentHardeningFields: []string{"field_a", "field_b"},
	}

	engine := NewEngine(rt, cm, cfg)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "agent"},
		Action:    "spectator.read",
		Resource: types.Resource{
			Type:     "spectator",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"field_a": {Classification: types.ClassificationPII},    // Should be hardened
				"field_b": {Classification: types.ClassificationPII},    // Should be hardened
				"field_c": {Classification: types.ClassificationPII},    // Not in hardening list
			},
		},
	}

	decision, _ := engine.Evaluate(input)
	if !decision.Allow {
		t.Fatalf("Expected allow for spectator.read")
	}

	// field_a and field_b should be masked (hardened)
	if decision.FieldActions["field_a"] != types.FieldActionMaskAfterDecrypt {
		t.Errorf("Expected field_a to be masked (hardened), got %s", decision.FieldActions["field_a"])
	}
	if decision.FieldActions["field_b"] != types.FieldActionMaskAfterDecrypt {
		t.Errorf("Expected field_b to be masked (hardened), got %s", decision.FieldActions["field_b"])
	}

	// field_c should NOT be hardened (decrypt as per role matrix)
	if decision.FieldActions["field_c"] != types.FieldActionDecrypt {
		t.Errorf("Expected field_c to be decrypt (not hardened), got %s", decision.FieldActions["field_c"])
	}
}

// TestEngine_RoleMatrixFromConfig verifies config-driven role×classification matrix
func TestEngine_RoleMatrixFromConfig(t *testing.T) {
	rt := runtime.New("on", 0)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Second,
		PepperTTL:         time.Minute,
	})

	// Custom role matrix (different from default)
	cfg := &dcsconfig.PDPConfig{
		DefaultClassification: types.ClassificationInternal,
		ReadActions:           []string{"test.read"},
		WriteActions:          []string{},
		BootstrapActions:      []string{},
		AuditActions:          []string{},
		RoleClassificationActions: map[string]map[string]string{
			"custom_role": {
				"PUBLIC":    "allow",
				"INTERNAL":  "deny",
				"SENSITIVE": "mask_after_decrypt",
				"PII":       "decrypt",
			},
		},
		SpectatorAgentHardeningFields: []string{},
	}

	engine := NewEngine(rt, cm, cfg)

	input := types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", UserID: "u1", Role: "custom_role"},
		Action:    "test.read",
		Resource: types.Resource{
			Type:     "test",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"public_field":    {Classification: types.ClassificationPublic},
				"internal_field":  {Classification: types.ClassificationInternal},
				"sensitive_field": {Classification: types.ClassificationSensitive},
				"pii_field":       {Classification: types.ClassificationPII},
			},
		},
	}

	decision, _ := engine.Evaluate(input)
	if !decision.Allow {
		t.Fatalf("Expected allow for test.read")
	}

	// Verify custom matrix is applied
	if decision.FieldActions["public_field"] != types.FieldActionAllow {
		t.Errorf("Expected public_field to be allow, got %s", decision.FieldActions["public_field"])
	}
	if decision.FieldActions["internal_field"] != types.FieldActionDeny {
		t.Errorf("Expected internal_field to be deny, got %s", decision.FieldActions["internal_field"])
	}
	if decision.FieldActions["sensitive_field"] != types.FieldActionMaskAfterDecrypt {
		t.Errorf("Expected sensitive_field to be mask_after_decrypt, got %s", decision.FieldActions["sensitive_field"])
	}
	if decision.FieldActions["pii_field"] != types.FieldActionDecrypt {
		t.Errorf("Expected pii_field to be decrypt, got %s", decision.FieldActions["pii_field"])
	}
}

// TestParseFieldAction verifies parsing of field action strings
func TestParseFieldAction(t *testing.T) {
	tests := []struct {
		input string
		want  types.FieldAction
	}{
		{"allow", types.FieldActionAllow},
		{"decrypt", types.FieldActionDecrypt},
		{"mask_after_decrypt", types.FieldActionMaskAfterDecrypt},
		{"deny", types.FieldActionDeny},
		{"unknown", types.FieldActionDeny}, // Unknown defaults to deny
		{"", types.FieldActionDeny},        // Empty defaults to deny
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseFieldAction(tc.input)
			if got != tc.want {
				t.Errorf("parseFieldAction(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
