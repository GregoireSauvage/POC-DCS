package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

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

// SpectatorCreatePlain represents plaintext spectator data before encryption
// Used as input to DCS enforcer for authorization + encryption
type SpectatorCreatePlain struct {
	HallID     string
	Name       string
	Age        int
	ExternalID string
}

// SpectatorCreateEncrypted represents spectator data after encryption by DCS enforcer
// Ready for database persistence, includes HMAC lookup for searchable encryption
type SpectatorCreateEncrypted struct {
	HallID           string
	NameCT           string // Encrypted name
	AgeCT            string // Encrypted age
	ExternalIDCT     string // Encrypted external_id
	ExternalIDLookup []byte // HMAC for searchable encryption
}

// SpectatorOutput is the API response structure for a spectator
type SpectatorOutput struct {
	ID         interface{} `json:"id"`          // UUID or masked string ("550e…")
	HallID     string      `json:"hall_id"`
	Name       interface{} `json:"name"`        // string (decrypted), string (masked), or nil
	Age        interface{} `json:"age"`         // int (decrypted), string (masked), or nil
	ExternalID interface{} `json:"external_id"` // string (decrypted), string (masked), or nil
}

// SpectatorReadInput is the input for enforcing read policy
type SpectatorReadInput struct {
	SpectatorID  string
	HallID       string
	NameCT       string
	AgeCT        string
	ExternalIDCT string
}

// SpectatorReadResult is the result after applying read policy
type SpectatorReadResult struct {
	Name            interface{} // string or nil
	Age             interface{} // int, string, or nil
	ExternalID      interface{} // string or nil
	FieldsDecrypted []string
	FieldsMasked    []string
	FieldsDenied    []string
}
