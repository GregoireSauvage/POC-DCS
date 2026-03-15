package config

import (
	"strings"

	legacytypes "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type PDPPolicy struct {
	cfg *PDPConfig
}

func NewPDPPolicy(cfg *PDPConfig) *PDPPolicy {
	return &PDPPolicy{cfg: cfg}
}

func (p *PDPPolicy) DefaultClassification() service.Classification {
	return toServiceClassification(p.cfg.DefaultClassification)
}

func (p *PDPPolicy) IsReadAction(action service.Action) bool {
	return contains(p.cfg.ReadActions, string(action))
}

func (p *PDPPolicy) IsWriteAction(action service.Action) bool {
	return contains(p.cfg.WriteActions, string(action))
}

func (p *PDPPolicy) IsBootstrapAction(action service.Action) bool {
	return contains(p.cfg.BootstrapActions, string(action))
}

func (p *PDPPolicy) IsAuditAction(action service.Action) bool {
	return contains(p.cfg.AuditActions, string(action))
}

func (p *PDPPolicy) FieldActionFor(role string, cls service.Classification) service.FieldAction {
	roleMatrix, ok := p.cfg.RoleClassificationActions[strings.ToLower(role)]
	if !ok {
		return service.FieldActionDeny
	}
	action, ok := roleMatrix[string(cls)]
	if !ok {
		return service.FieldActionDeny
	}
	return toServiceFieldAction(action)
}

func (p *PDPPolicy) HardenedFields(resourceType string, role string) []string {
	if resourceType != "spectator" || !strings.EqualFold(role, "agent") {
		return nil
	}
	return append([]string(nil), p.cfg.SpectatorAgentHardeningFields...)
}

func toServiceClassification(cls legacytypes.Classification) service.Classification {
	switch cls {
	case legacytypes.ClassificationPublic:
		return service.ClassificationPublic
	case legacytypes.ClassificationInternal:
		return service.ClassificationInternal
	case legacytypes.ClassificationSensitive:
		return service.ClassificationSensitive
	case legacytypes.ClassificationPII:
		return service.ClassificationPII
	default:
		return service.Classification(cls)
	}
}

func toServiceFieldAction(action string) service.FieldAction {
	switch action {
	case string(service.FieldActionAllow):
		return service.FieldActionAllow
	case string(service.FieldActionDecrypt):
		return service.FieldActionDecrypt
	case string(service.FieldActionMaskAfterDecrypt):
		return service.FieldActionMaskAfterDecrypt
	default:
		return service.FieldActionDeny
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

var _ service.ClassificationPolicy = (*PDPPolicy)(nil)
