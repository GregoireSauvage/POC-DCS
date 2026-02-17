package enforcer

import (
	"context"
	"fmt"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
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

// EnforceSpectatorCreate authorizes, encrypts PII fields AND computes HMAC lookup
// Combines PDP (authorization) + PEP (encryption + HMAC) in a single operation
// Returns encrypted data ready for database persistence with searchable encryption
func (e *DcsEnforcer) EnforceSpectatorCreate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	input service.SpectatorCreatePlain,
) (service.SpectatorCreateEncrypted, error) {

	// Phase 1: PIP - Build policy input
	pipInput := pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "spectator.create",
		ResourceType: "spectator",
		ResourceID:   "",
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta: map[string]map[string]string{
			"name":        {"ciphertext_field": "name_ct"},
			"age":         {"ciphertext_field": "age_ct"},
			"external_id": {"ciphertext_field": "external_id_ct"},
		},
	}

	policyInput, err := e.pip.Build(ctx, pipInput)
	if err != nil {
		return service.SpectatorCreateEncrypted{}, fmt.Errorf("pip build failed: %w", err)
	}

	// Phase 2: PDP - Evaluate authorization
	stop := perf.Span(ctx, "pdp_ms")
	decision, _ := e.pdp.Evaluate(policyInput)
	stop()

	if !decision.Allow {
		return service.SpectatorCreateEncrypted{}, service.ErrForbidden
	}

	// Phase 3: PEP - Encrypt all PII fields
	stop = perf.Span(ctx, "kms_ms")

	nameCT, err := e.kms.Encrypt(ctx, input.Name)
	if err != nil {
		stop()
		return service.SpectatorCreateEncrypted{}, fmt.Errorf("encrypt name: %w", err)
	}

	ageCT, err := e.kms.Encrypt(ctx, strconv.Itoa(input.Age))
	if err != nil {
		stop()
		return service.SpectatorCreateEncrypted{}, fmt.Errorf("encrypt age: %w", err)
	}

	externalIDCT, err := e.kms.Encrypt(ctx, input.ExternalID)
	if err != nil {
		stop()
		return service.SpectatorCreateEncrypted{}, fmt.Errorf("encrypt external_id: %w", err)
	}

	stop()

	// Phase 4: PEP - Compute HMAC lookup for searchable encryption
	pepper, err := e.kms.GetPepper(ctx, e.pepperPath)
	if err != nil {
		return service.SpectatorCreateEncrypted{}, fmt.Errorf("get pepper: %w", err)
	}

	normalized := kms.NormalizeExternalID(input.ExternalID)
	lookup := kms.ComputeHMACLookup(pepper, normalized)

	return service.SpectatorCreateEncrypted{
		HallID:           input.HallID,
		NameCT:           nameCT,
		AgeCT:            ageCT,
		ExternalIDCT:     externalIDCT,
		ExternalIDLookup: lookup,
	}, nil
}
