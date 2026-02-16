package enforcer

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// EvaluateSpectatorCreate evaluates the spectator.create action
func (e *DcsEnforcer) EvaluateSpectatorCreate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	ownerUserID string,
) (service.AuthorizationDecision, error) {
	// Build policy input
	pipInput := pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "spectator.create",
		ResourceType: "spectator",
		ResourceID:   "",
		OwnerID:      ownerUserID,
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta: map[string]map[string]string{
			"name":        {"ciphertext_field": "name_ct"},
			"age":         {"ciphertext_field": "age_ct"},
			"external_id": {"ciphertext_field": "external_id_ct"},
		},
	}

	policyInput, err := e.pip.Build(ctx, pipInput)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	// Evaluate policy
	decision, _ := e.pdp.Evaluate(policyInput)
	return service.AuthorizationDecision{
		Allow:        decision.Allow,
		Reason:       decision.Reason,
		DecisionHash: decision.Hash,
	}, nil
}

// EvaluateSpectatorSearch evaluates the search.spectator action
func (e *DcsEnforcer) EvaluateSpectatorSearch(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
) (service.AuthorizationDecision, error) {
	// Build policy input
	pipInput := pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "search.spectator",
		ResourceType: "spectator",
		ResourceID:   "search",
		OwnerID:      "",
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta: map[string]map[string]string{
			"name":        {"ciphertext_field": "name_ct"},
			"age":         {"ciphertext_field": "age_ct"},
			"external_id": {"ciphertext_field": "external_id_ct"},
		},
	}

	policyInput, err := e.pip.Build(ctx, pipInput)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	// Evaluate policy
	decision, _ := e.pdp.Evaluate(policyInput)
	return service.AuthorizationDecision{
		Allow:        decision.Allow,
		Reason:       decision.Reason,
		DecisionHash: decision.Hash,
	}, nil
}

// EnforceSpectatorRead applies field-level enforcement for spectator.read
func (e *DcsEnforcer) EnforceSpectatorRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	spectator service.SpectatorReadInput,
) (service.SpectatorReadResult, error) {
	// Build policy input
	pipInput := pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "spectator.read",
		ResourceType: "spectator",
		ResourceID:   spectator.SpectatorID,
		OwnerID:      "", // Spectators don't have direct owner, use hall's owner
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta: map[string]map[string]string{
			"name":        {"ciphertext_field": "name_ct"},
			"age":         {"ciphertext_field": "age_ct"},
			"external_id": {"ciphertext_field": "external_id_ct"},
		},
	}

	policyInput, err := e.pip.Build(ctx, pipInput)
	if err != nil {
		return service.SpectatorReadResult{}, err
	}

	// Evaluate policy
	decision, _ := e.pdp.Evaluate(policyInput)

	// Apply field actions using SpectatorApplier
	row := pep.SpectatorRow{
		ID:           spectator.SpectatorID,
		HallID:       spectator.HallID,
		NameCT:       spectator.NameCT,
		AgeCT:        spectator.AgeCT,
		ExternalIDCT: spectator.ExternalIDCT,
	}

	applied, err := e.spectatorApplier.Apply(ctx, decision, row)
	if err != nil {
		return service.SpectatorReadResult{}, err
	}

	// Convert to service result
	result := service.SpectatorReadResult{
		Name:            applied.Payload["name"],
		Age:             applied.Payload["age"],
		ExternalID:      applied.Payload["external_id"],
		FieldsDecrypted: applied.Decrypted,
		FieldsMasked:    applied.Masked,
		FieldsDenied:    applied.Denied,
	}

	return result, nil
}
