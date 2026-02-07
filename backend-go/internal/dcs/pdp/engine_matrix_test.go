package pdp

import (
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func TestActionForClassification_Matrix(t *testing.T) {
	tests := []struct {
		name string
		role string
		cls  types.Classification
		want types.FieldAction
	}{
		{"admin public", "admin", types.ClassificationPublic, types.FieldActionAllow},
		{"admin sensitive", "admin", types.ClassificationSensitive, types.FieldActionDecrypt},
		{"admin pii", "admin", types.ClassificationPII, types.FieldActionDecrypt},
		{"agent public", "agent", types.ClassificationPublic, types.FieldActionAllow},
		{"agent sensitive", "agent", types.ClassificationSensitive, types.FieldActionDecrypt},
		{"agent pii", "agent", types.ClassificationPII, types.FieldActionMaskAfterDecrypt},
		{"developer public", "developer", types.ClassificationPublic, types.FieldActionAllow},
		{"developer internal", "developer", types.ClassificationInternal, types.FieldActionMaskAfterDecrypt},
		{"unknown role", "visitor", types.ClassificationPublic, types.FieldActionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := actionForClassification(tc.role, tc.cls)
			if got != tc.want {
				t.Fatalf("actionForClassification(%q, %q)=%q, want %q", tc.role, tc.cls, got, tc.want)
			}
		})
	}
}

func TestAllowWithoutDCS_Matrix(t *testing.T) {
	tests := []struct {
		name   string
		action string
		role   string
		want   bool
	}{
		{"read allowed", "film.read", "developer", true},
		{"write denied developer", "film.create", "developer", false},
		{"write allowed agent", "film.create", "agent", true},
		{"write allowed admin", "film.update_time", "admin", true},
		{"audit denied agent", "audit.read", "agent", false},
		{"audit allowed admin", "audit.read", "admin", true},
		{"unknown action", "x.y", "admin", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowWithoutDCS(tc.action, tc.role); got != tc.want {
				t.Fatalf("allowWithoutDCS(%q,%q)=%v, want %v", tc.action, tc.role, got, tc.want)
			}
		})
	}
}

func TestDecide_AuditAndUnknownRoleFieldActions(t *testing.T) {
	auditDenied := decide(types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", Role: "agent"},
		Action:    "audit.read",
		Resource:  types.Resource{TenantID: "t1"},
	})
	if auditDenied.Allow {
		t.Fatalf("expected agent denied for audit.read")
	}
	if auditDenied.Reason != "audit_admin_only" {
		t.Fatalf("unexpected reason: %q", auditDenied.Reason)
	}

	readUnknown := decide(types.PolicyInput{
		Principal: types.Principal{TenantID: "t1", Role: "visitor"},
		Action:    "film.read",
		Resource: types.Resource{
			Type:     "film",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"title": {Classification: types.ClassificationPublic},
			},
		},
	})
	if !readUnknown.Allow {
		t.Fatalf("expected read to be allowed before field-level policy")
	}
	if readUnknown.FieldActions["title"] != types.FieldActionDeny {
		t.Fatalf("expected unknown role to be denied at field level")
	}
}

func TestDecisionCacheKey_DcsModeChangesKey(t *testing.T) {
	input := types.PolicyInput{
		Principal: types.Principal{
			TenantID: "t1",
			UserID:   "u1",
			Role:     "developer",
		},
		Action: "film.read",
		Resource: types.Resource{
			Type:     "film",
			TenantID: "t1",
			Fields: map[string]types.FieldMeta{
				"title": {Classification: types.ClassificationPublic},
			},
		},
	}

	onKey := decisionCacheKey(true, input)
	offKey := decisionCacheKey(false, input)
	if onKey == offKey {
		t.Fatalf("expected dcs mode to impact decision cache key")
	}
}
