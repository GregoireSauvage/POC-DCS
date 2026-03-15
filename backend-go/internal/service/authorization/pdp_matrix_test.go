package authorization

import (
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestPDP_RoleClassificationMatrix(t *testing.T) {
	pdp := NewPDP(buildTestPolicy())
	tests := []struct {
		name string
		role string
		cls  service.Classification
		want service.FieldAction
	}{
		{name: "admin public", role: "admin", cls: service.ClassificationPublic, want: service.FieldActionAllow},
		{name: "admin internal", role: "admin", cls: service.ClassificationInternal, want: service.FieldActionAllow},
		{name: "admin sensitive", role: "admin", cls: service.ClassificationSensitive, want: service.FieldActionDecrypt},
		{name: "admin pii", role: "admin", cls: service.ClassificationPII, want: service.FieldActionDecrypt},
		{name: "agent public", role: "agent", cls: service.ClassificationPublic, want: service.FieldActionAllow},
		{name: "agent internal", role: "agent", cls: service.ClassificationInternal, want: service.FieldActionAllow},
		{name: "agent sensitive", role: "agent", cls: service.ClassificationSensitive, want: service.FieldActionDecrypt},
		{name: "agent pii", role: "agent", cls: service.ClassificationPII, want: service.FieldActionMaskAfterDecrypt},
		{name: "developer public", role: "developer", cls: service.ClassificationPublic, want: service.FieldActionAllow},
		{name: "developer internal", role: "developer", cls: service.ClassificationInternal, want: service.FieldActionMaskAfterDecrypt},
		{name: "developer sensitive", role: "developer", cls: service.ClassificationSensitive, want: service.FieldActionMaskAfterDecrypt},
		{name: "developer pii", role: "developer", cls: service.ClassificationPII, want: service.FieldActionMaskAfterDecrypt},
		{name: "unknown role", role: "visitor", cls: service.ClassificationPublic, want: service.FieldActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := pdp.Evaluate(buildTestInput(service.ActionFilmRead, tt.role, "film", "t1", map[string]service.FieldMeta{
				"field": {Classification: tt.cls},
			}))
			if got := decision.FieldActions["field"]; got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
