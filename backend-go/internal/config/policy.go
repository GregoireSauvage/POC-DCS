package config

import (
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type ClassificationPolicyAdapter struct {
	cfg *DCSConfig
}

func NewClassificationPolicy(cfg *DCSConfig) *ClassificationPolicyAdapter {
	if cfg == nil {
		cfg = DefaultDCSConfig()
	}
	applyDCSDefaults(cfg)
	return &ClassificationPolicyAdapter{cfg: cfg}
}

func (p *ClassificationPolicyAdapter) PolicyID() string {
	return p.cfg.Policy.PolicyID
}

func (p *ClassificationPolicyAdapter) PolicyVersion() string {
	return p.cfg.Policy.PolicyVersion
}

func (p *ClassificationPolicyAdapter) DefaultClassification() service.Classification {
	return p.cfg.PDP.DefaultClassification
}

func (p *ClassificationPolicyAdapter) IsReadAction(action service.Action) bool {
	return containsString(p.cfg.PDP.ReadActions, string(action))
}

func (p *ClassificationPolicyAdapter) IsWriteAction(action service.Action) bool {
	return containsString(p.cfg.PDP.WriteActions, string(action))
}

func (p *ClassificationPolicyAdapter) IsBootstrapAction(action service.Action) bool {
	return containsString(p.cfg.PDP.BootstrapActions, string(action))
}

func (p *ClassificationPolicyAdapter) IsAuditAction(action service.Action) bool {
	return containsString(p.cfg.PDP.AuditActions, string(action))
}

func (p *ClassificationPolicyAdapter) FieldActionFor(role string, cls service.Classification) service.FieldAction {
	roleMatrix, ok := p.cfg.PDP.RoleClassificationActions[strings.ToLower(role)]
	if !ok {
		return service.FieldActionDeny
	}
	action, ok := roleMatrix[string(cls)]
	if !ok {
		return service.FieldActionDeny
	}
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

func (p *ClassificationPolicyAdapter) HardenedFields(resourceType string, role string) []string {
	if resourceType != "spectator" || !strings.EqualFold(role, "agent") {
		return nil
	}
	return append([]string(nil), p.cfg.PDP.SpectatorAgentHardeningFields...)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

var _ service.ClassificationPolicy = (*ClassificationPolicyAdapter)(nil)
