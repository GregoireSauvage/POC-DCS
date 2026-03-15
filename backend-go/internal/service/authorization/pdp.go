package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type PDP struct {
	policy service.ClassificationPolicy
}

func NewPDP(policy service.ClassificationPolicy) *PDP {
	return &PDP{policy: policy}
}

func (p *PDP) Evaluate(input service.PolicyInput) service.Decision {
	decision := p.decide(input)
	decision.Hash = DecisionHash(decision)
	return decision
}

func DecisionHash(decision service.Decision) string {
	fieldKeys := make([]string, 0, len(decision.FieldActions))
	for key := range decision.FieldActions {
		fieldKeys = append(fieldKeys, key)
	}
	sort.Strings(fieldKeys)

	sortedActions := make(map[string]service.FieldAction, len(decision.FieldActions))
	for _, key := range fieldKeys {
		sortedActions[key] = decision.FieldActions[key]
	}

	payload := map[string]any{
		"allow":         decision.Allow,
		"field_actions": sortedActions,
		"reason":        decision.Reason,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (p *PDP) decide(input service.PolicyInput) service.Decision {
	if input.Access.Principal.TenantID != input.Resource.TenantID {
		return service.Decision{Allow: false, FieldActions: map[string]service.FieldAction{}, Reason: "tenant_mismatch"}
	}

	action := input.Access.Action
	allow := false
	reason := "default_deny"

	switch {
	case p.policy.IsReadAction(action):
		allow = true
		reason = "read_allowed"
	case p.policy.IsWriteAction(action):
		allow = input.Access.Principal.Role == "agent" || input.Access.Principal.Role == "admin"
		if allow {
			reason = "write_allowed"
		} else {
			reason = "write_forbidden"
		}
	case p.policy.IsBootstrapAction(action):
		allow = true
		reason = "bootstrap_allowed"
	case p.policy.IsAuditAction(action):
		allow = input.Access.Principal.Role == "admin"
		if allow {
			reason = "audit_allowed"
		} else {
			reason = "audit_admin_only"
		}
	default:
		return service.Decision{Allow: false, FieldActions: map[string]service.FieldAction{}, Reason: "unknown_action"}
	}

	if !allow {
		return service.Decision{Allow: false, FieldActions: map[string]service.FieldAction{}, Reason: reason}
	}

	fieldActions := make(map[string]service.FieldAction, len(input.Resource.Fields))
	for field, meta := range input.Resource.Fields {
		classification := meta.Classification
		if classification == "" {
			classification = p.policy.DefaultClassification()
		}
		fieldActions[field] = p.policy.FieldActionFor(input.Access.Principal.Role, classification)
	}

	if input.Resource.Type == "spectator" && input.Access.Principal.Role == "agent" {
		for _, field := range p.policy.HardenedFields(input.Resource.Type, input.Access.Principal.Role) {
			if _, ok := fieldActions[field]; ok {
				fieldActions[field] = service.FieldActionMaskAfterDecrypt
			}
		}
	}

	return service.Decision{Allow: true, FieldActions: fieldActions, Reason: reason}
}
