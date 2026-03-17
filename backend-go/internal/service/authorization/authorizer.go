package authorization

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type PolicyAuthorizer struct {
	runtime service.RuntimeSettings
	pdp     *PDP
}

func NewAuthorizer(runtime service.RuntimeSettings, pdp *PDP) *PolicyAuthorizer {
	return &PolicyAuthorizer{
		runtime: runtime,
		pdp:     pdp,
	}
}

func (a *PolicyAuthorizer) Authorize(ctx context.Context, input service.PolicyInput) (service.Decision, error) {
	_ = ctx

	if a.runtime == nil || a.pdp == nil {
		return service.Decision{}, nil
	}
	if !a.runtime.DcsEnabled() {
		decision := service.Decision{
			Allow:        a.allowWithoutDCS(input.Access.Action, input.Access.Principal.Role),
			FieldActions: map[string]service.FieldAction{},
			Reason:       "dcs_off",
			PolicyID:     a.pdp.policy.PolicyID(),
			PolicyVersion: a.pdp.policy.PolicyVersion(),
		}
		decision.Hash = DecisionHash(decision)
		return decision, nil
	}
	return a.pdp.Evaluate(input), nil
}

func (a *PolicyAuthorizer) allowWithoutDCS(action service.Action, role string) bool {
	switch {
	case a.pdp.policy.IsReadAction(action):
		return true
	case a.pdp.policy.IsWriteAction(action):
		return role == "agent" || role == "admin"
	case a.pdp.policy.IsBootstrapAction(action):
		return true
	case a.pdp.policy.IsAuditAction(action):
		return role == "admin"
	default:
		return false
	}
}
