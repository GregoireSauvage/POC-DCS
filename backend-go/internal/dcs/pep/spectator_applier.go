package pep

import (
	"context"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

// SpectatorRow represents encrypted spectator data from database
type SpectatorRow struct {
	ID           string
	HallID       string
	NameCT       string
	AgeCT        string
	ExternalIDCT string
}

// SpectatorApplyResult contains the result after applying field actions
type SpectatorApplyResult struct {
	Payload   map[string]interface{}
	Decrypted []string
	Masked    []string
	Denied    []string
}

// SpectatorApplier applies DCS field actions to spectator data
type SpectatorApplier struct {
	kms Decryptor
}

// NewSpectatorApplier creates a new spectator applier
func NewSpectatorApplier(kms Decryptor) *SpectatorApplier {
	return &SpectatorApplier{kms: kms}
}

// Apply applies field actions from PDP decision to spectator row
// Python parity: data_pep.py:43-122 (apply_decision)
func (a *SpectatorApplier) Apply(
	ctx context.Context,
	decision types.Decision,
	row SpectatorRow,
) (SpectatorApplyResult, error) {
	result := SpectatorApplyResult{
		Payload:   make(map[string]interface{}),
		Decrypted: []string{},
		Masked:    []string{},
		Denied:    []string{},
	}

	if !decision.Allow {
		result.Denied = []string{"name", "age", "external_id"}
		return result, nil
	}

	// Map fields to their ciphertext
	fieldMap := map[string]string{
		"name":        row.NameCT,
		"age":         row.AgeCT,
		"external_id": row.ExternalIDCT,
	}

	for field, ciphertext := range fieldMap {
		action, ok := decision.FieldActions[field]
		if !ok {
			// No action specified, default to deny
			result.Payload[field] = nil
			result.Denied = append(result.Denied, field)
			continue
		}

		switch action {
		case types.FieldActionDeny:
			result.Payload[field] = nil
			result.Denied = append(result.Denied, field)

		case types.FieldActionDecrypt:
			plaintext, err := a.kms.Decrypt(ctx, ciphertext)
			if err != nil {
				return SpectatorApplyResult{}, err
			}

			// Convert age to int
			if field == "age" {
				age, err := strconv.Atoi(plaintext)
				if err != nil {
					result.Payload[field] = plaintext
				} else {
					result.Payload[field] = age
				}
			} else {
				result.Payload[field] = plaintext
			}
			result.Decrypted = append(result.Decrypted, field)

		case types.FieldActionMaskAfterDecrypt:
			plaintext, err := a.kms.Decrypt(ctx, ciphertext)
			if err != nil {
				return SpectatorApplyResult{}, err
			}

			// Apply field-specific masking
			masked := ApplyMask(field, plaintext)
			result.Payload[field] = masked
			result.Masked = append(result.Masked, field)

		default:
			// Unknown action, deny
			result.Payload[field] = nil
			result.Denied = append(result.Denied, field)
		}
	}

	return result, nil
}
