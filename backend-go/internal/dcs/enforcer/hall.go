package enforcer

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// EvaluateHallCreate evaluates the hall.create action
func (e *DcsEnforcer) EvaluateHallCreate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	ownerUserID string,
) (service.AuthorizationDecision, error) {
	policyInput, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       string(service.ActionHallCreate),
		ResourceType: "hall",
		OwnerID:      ownerUserID,
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	decision, err := e.authorizePolicyInput(ctx, policyInput)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}
	return service.AuthorizationDecision{
		Allow:        decision.Allow,
		Reason:       decision.Reason,
		DecisionHash: decision.Hash,
		PolicyID:     decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
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
	policyInput, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       string(service.ActionHallRead),
		ResourceType: "hall",
		ResourceID:   hallID,
		OwnerID:      ownerUserID,
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	decision, err := e.authorizePolicyInput(ctx, policyInput)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}
	return service.AuthorizationDecision{
		Allow:        decision.Allow,
		Reason:       decision.Reason,
		DecisionHash: decision.Hash,
		PolicyID:     decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
	}, nil
}

// EnforceHallRead applies field-level enforcement for hall.read
func (e *DcsEnforcer) EnforceHallRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	hall service.HallReadInput,
) (service.HallReadResult, error) {
	policyInput, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       string(service.ActionHallRead),
		ResourceType: "hall",
		ResourceID:   hall.HallID,
		OwnerID:      hall.OwnerUserID,
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.HallReadResult{}, err
	}

	decision, err := e.authorizePolicyInput(ctx, policyInput)
	if err != nil {
		return service.HallReadResult{}, err
	}

	result := service.HallReadResult{}
	name := hall.Name
	result.Name = &name
	result.DecisionHash = decision.Hash
	result.PolicyID = decision.PolicyID
	result.PolicyVersion = decision.PolicyVersion

	if decision.FieldActions["owner_user_id"] == service.FieldActionMaskAfterDecrypt {
		result.OwnerUserID = pep.MaskUUID(hall.OwnerUserID)
		result.FieldsMasked = append(result.FieldsMasked, "owner_user_id")
	} else {
		result.OwnerUserID = hall.OwnerUserID
	}

	if decision.FieldActions["current_film_id"] == service.FieldActionMaskAfterDecrypt {
		result.CurrentFilmID = pep.MaskUUID(hall.CurrentFilmID)
		result.FieldsMasked = append(result.FieldsMasked, "current_film_id")
	} else {
		result.CurrentFilmID = hall.CurrentFilmID
	}

	return result, nil
}
