package authorization

import (
	"testing"

	dcsconfig "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func buildTestPolicy() service.ClassificationPolicy {
	cfg := dcsconfig.Defaults()
	return dcsconfig.NewPDPPolicy(&cfg.PDP)
}

func buildTestInput(action service.Action, role string, resourceType string, resourceTenant string, fields map[string]service.FieldMeta) service.PolicyInput {
	return service.PolicyInput{
		Access: service.AccessContext{
			Principal: service.Principal{TenantID: "t1", UserID: "u-1", Role: role},
			Action:    action,
		},
		Resource: service.Resource{
			Type:     resourceType,
			TenantID: resourceTenant,
			Fields:   fields,
		},
	}
}

func TestPDP_TenantMismatch(t *testing.T) {
	pdp := NewPDP(buildTestPolicy())
	decision := pdp.Evaluate(buildTestInput(service.ActionFilmRead, "admin", "film", "other-tenant", map[string]service.FieldMeta{}))
	if decision.Allow {
		t.Fatalf("expected deny on tenant mismatch")
	}
	if decision.Reason != "tenant_mismatch" {
		t.Fatalf("expected tenant_mismatch, got %q", decision.Reason)
	}
}

func TestPDP_UnknownAction(t *testing.T) {
	pdp := NewPDP(buildTestPolicy())
	decision := pdp.Evaluate(buildTestInput(service.Action("unknown"), "admin", "film", "t1", nil))
	if decision.Allow {
		t.Fatalf("expected deny on unknown action")
	}
	if decision.Reason != "unknown_action" {
		t.Fatalf("expected unknown_action, got %q", decision.Reason)
	}
}

func TestPDP_SpectatorAgentHardening(t *testing.T) {
	pdp := NewPDP(buildTestPolicy())
	decision := pdp.Evaluate(buildTestInput(service.ActionSpectatorRead, "agent", "spectator", "t1", map[string]service.FieldMeta{
		"name":        {Classification: service.ClassificationPII},
		"age":         {Classification: service.ClassificationSensitive},
		"external_id": {Classification: service.ClassificationPII},
	}))

	if decision.FieldActions["name"] != service.FieldActionMaskAfterDecrypt {
		t.Fatalf("expected agent hardening on name, got %q", decision.FieldActions["name"])
	}
	if decision.FieldActions["external_id"] != service.FieldActionMaskAfterDecrypt {
		t.Fatalf("expected agent hardening on external_id, got %q", decision.FieldActions["external_id"])
	}
	if decision.FieldActions["age"] != service.FieldActionDecrypt {
		t.Fatalf("expected age to stay decrypt, got %q", decision.FieldActions["age"])
	}
}

func TestDecisionHash_Deterministic(t *testing.T) {
	decisionA := service.Decision{
		Allow: true,
		FieldActions: map[string]service.FieldAction{
			"zzz": service.FieldActionDecrypt,
			"aaa": service.FieldActionAllow,
		},
		Reason: "read_allowed",
	}
	decisionB := service.Decision{
		Allow: true,
		FieldActions: map[string]service.FieldAction{
			"aaa": service.FieldActionAllow,
			"zzz": service.FieldActionDecrypt,
		},
		Reason: "read_allowed",
	}

	if DecisionHash(decisionA) != DecisionHash(decisionB) {
		t.Fatalf("expected deterministic decision hash")
	}
}
