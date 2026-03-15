package enforcer

import (
	legacytypes "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func toServicePolicyInput(input legacytypes.PolicyInput) service.PolicyInput {
	fields := make(map[string]service.FieldMeta, len(input.Resource.Fields))
	for name, meta := range input.Resource.Fields {
		fields[name] = service.FieldMeta{
			Classification: toServiceClassification(meta.Classification),
			Crypto:         cloneStringMap(meta.Crypto),
		}
	}

	labels := append([]string(nil), input.Resource.Labels...)

	return service.PolicyInput{
		Access: service.AccessContext{
			Principal: service.Principal{
				TenantID: input.Principal.TenantID,
				UserID:   input.Principal.UserID,
				Username: input.Principal.Username,
				Role:     input.Principal.Role,
				Scopes:   append([]string(nil), input.Principal.Scopes...),
			},
			Request: service.RequestContext{
				RequestID:   input.Context.RequestID,
				ClientIP:    input.Context.ClientIP,
				Channel:     input.Context.Channel,
				Purpose:     input.Context.Purpose,
				DeviceTrust: input.Context.DeviceTrust,
				Env:         input.Context.Env,
			},
			Action: service.Action(input.Action),
		},
		Resource: service.Resource{
			Type:     input.Resource.Type,
			ID:       input.Resource.ID,
			OwnerID:  input.Resource.OwnerID,
			TenantID: input.Resource.TenantID,
			Labels:   labels,
			Fields:   fields,
		},
	}
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

func toDCSDecision(decision service.Decision) legacytypes.Decision {
	fieldActions := make(map[string]legacytypes.FieldAction, len(decision.FieldActions))
	for field, action := range decision.FieldActions {
		fieldActions[field] = toDCSFieldAction(action)
	}
	return legacytypes.Decision{
		Allow:        decision.Allow,
		FieldActions: fieldActions,
		Reason:       decision.Reason,
		Hash:         decision.Hash,
	}
}

func toDCSFieldAction(action service.FieldAction) legacytypes.FieldAction {
	switch action {
	case service.FieldActionAllow:
		return legacytypes.FieldActionAllow
	case service.FieldActionDecrypt:
		return legacytypes.FieldActionDecrypt
	case service.FieldActionMaskAfterDecrypt:
		return legacytypes.FieldActionMaskAfterDecrypt
	default:
		return legacytypes.FieldActionDeny
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
