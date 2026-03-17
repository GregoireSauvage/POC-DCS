package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

const DefaultSpectatorPepperPath = "secret/dcs" // Python parity: config.VAULT_KV_PEPPER_PATH

// SpectatorRepository defines operations for spectator persistence
type SpectatorRepository interface {
	Create(ctx context.Context, spectator *domain.Spectator) error
	FindByExternalIDLookup(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error)
	CountByHall(ctx context.Context, tenantID, hallID string) (int, error)
}

// SpectatorCreateInput is the HTTP request input for creating a spectator
type SpectatorCreateInput struct {
	HallID     string `json:"hall_id"`
	Name       string `json:"name"`
	Age        int    `json:"age"`
	ExternalID string `json:"external_id"`
}

// SpectatorOutput is the API response structure for a spectator
type SpectatorOutput struct {
	ID         interface{} `json:"id"` // UUID or masked string ("550e…")
	HallID     string      `json:"hall_id"`
	Name       interface{} `json:"name"`        // string (decrypted), string (masked), or nil
	Age        interface{} `json:"age"`         // int (decrypted), string (masked), or nil
	ExternalID interface{} `json:"external_id"` // string (decrypted), string (masked), or nil
}

type SpectatorReadView struct {
	Output          SpectatorOutput
	FieldsDecrypted []string
	FieldsMasked    []string
	FieldsDenied    []string
	DecisionHash    string
	PolicyID        string
	PolicyVersion   string
}

type SpectatorReadCandidate struct {
	Record   *domain.Spectator
	Resource Resource
}

type SecureSpectatorRepository interface {
	Create(ctx context.Context, tenantID string, input SpectatorCreateInput, decision Decision) (SpectatorReadCandidate, error)
	SearchCandidatesByExternalID(ctx context.Context, tenantID string, externalID string, decision Decision) ([]SpectatorReadCandidate, error)
	ApplyReadDecision(ctx context.Context, candidate SpectatorReadCandidate, decision Decision) (SpectatorReadView, error)
}
