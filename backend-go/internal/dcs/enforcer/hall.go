package enforcer

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// EvaluateHallCreate evaluates the hall.create action
func (e *DcsEnforcer) EvaluateHallCreate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	ownerUserID string,
) (service.AuthorizationDecision, error) {
	// Build policy input
	pipInput := pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "hall.create",
		ResourceType: "hall",
		ResourceID:   "",
		OwnerID:      ownerUserID,
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta:   nil, // Halls have no encrypted fields
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

// EvaluateHallRead evaluates the hall.read action
func (e *DcsEnforcer) EvaluateHallRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	hallID string,
	ownerUserID string,
) (service.AuthorizationDecision, error) {
	// Build policy input
	pipInput := pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "hall.read",
		ResourceType: "hall",
		ResourceID:   hallID,
		OwnerID:      ownerUserID,
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta:   nil, // Halls have no encrypted fields
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

// EnforceHallRead applies field-level enforcement for hall.read
func (e *DcsEnforcer) EnforceHallRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	hall service.HallReadInput,
) (service.HallReadResult, error) {
	// Build policy input
	pipInput := pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "hall.read",
		ResourceType: "hall",
		ResourceID:   hall.HallID,
		OwnerID:      hall.OwnerUserID,
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta:   nil, // Halls have no encrypted fields
	}

	policyInput, err := e.pip.Build(ctx, pipInput)
	if err != nil {
		return service.HallReadResult{}, err
	}

	// Evaluate policy
	decision, _ := e.pdp.Evaluate(policyInput)

	result := service.HallReadResult{}
	fa := decision.FieldActions

	// Name: PUBLIC - visible for all roles, never denied
	name := hall.Name
	result.Name = &name

	// OwnerUserID: INTERNAL - masked for developer only
	if fa["owner_user_id"] == types.FieldActionMaskAfterDecrypt {
		result.OwnerUserID = pep.MaskUUID(hall.OwnerUserID)
		result.FieldsMasked = append(result.FieldsMasked, "owner_user_id")
	} else {
		result.OwnerUserID = hall.OwnerUserID
	}

	// CurrentFilmID: INTERNAL - masked for developer only
	if fa["current_film_id"] == types.FieldActionMaskAfterDecrypt {
		result.CurrentFilmID = pep.MaskUUID(hall.CurrentFilmID)
		result.FieldsMasked = append(result.FieldsMasked, "current_film_id")
	} else {
		result.CurrentFilmID = hall.CurrentFilmID
	}

	return result, nil
}

