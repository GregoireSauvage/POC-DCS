package authorization

import (
	"testing"

	appconfig "github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestPDPPolicy_DefaultMappings(t *testing.T) {
	cfg := appconfig.DefaultDCSConfig()
	policy := appconfig.NewClassificationPolicy(cfg)

	if !policy.IsReadAction(service.ActionFilmRead) {
		t.Fatalf("expected film.read to be a read action")
	}
	if !policy.IsWriteAction(service.ActionSpectatorCreate) {
		t.Fatalf("expected spectator.create to be a write action")
	}
	if !policy.IsAuditAction(service.ActionAuditRead) {
		t.Fatalf("expected audit.read to be an audit action")
	}
	if got := policy.DefaultClassification(); got != service.ClassificationInternal {
		t.Fatalf("expected INTERNAL default classification, got %q", got)
	}
	if got := policy.FieldActionFor("developer", service.ClassificationSensitive); got != service.FieldActionMaskAfterDecrypt {
		t.Fatalf("expected developer sensitive mapping to mask_after_decrypt, got %q", got)
	}
	if hardened := policy.HardenedFields("spectator", "agent"); len(hardened) != 2 {
		t.Fatalf("expected two hardened fields for spectator agent, got %d", len(hardened))
	}
	if got := policy.PolicyID(); got != "cinema-default" {
		t.Fatalf("expected policy id cinema-default, got %q", got)
	}
	if got := policy.PolicyVersion(); got != "v1" {
		t.Fatalf("expected policy version v1, got %q", got)
	}
}
