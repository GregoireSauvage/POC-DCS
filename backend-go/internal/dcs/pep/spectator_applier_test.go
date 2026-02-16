package pep

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type mockDecryptor struct {
	decryptFn func(ctx context.Context, ciphertext string) (string, error)
}

func (m *mockDecryptor) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, ciphertext)
	}
	return "", nil
}

func TestSpectatorApplier_AdminDecryptsAll(t *testing.T) {
	ctx := context.Background()
	decryptor := &mockDecryptor{
		decryptFn: func(ctx context.Context, ct string) (string, error) {
			switch ct {
			case "name-ct":
				return "John Doe", nil
			case "age-ct":
				return "25", nil
			case "external-id-ct":
				return "ABC123", nil
			default:
				return "", nil
			}
		},
	}

	applier := NewSpectatorApplier(decryptor)

	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"name":        types.FieldActionDecrypt,
			"age":         types.FieldActionDecrypt,
			"external_id": types.FieldActionDecrypt,
		},
	}

	row := SpectatorRow{
		ID:           "spectator-1",
		HallID:       "hall-1",
		NameCT:       "name-ct",
		AgeCT:        "age-ct",
		ExternalIDCT: "external-id-ct",
	}

	result, err := applier.Apply(ctx, decision, row)
	require.NoError(t, err)

	assert.Equal(t, "John Doe", result.Payload["name"])
	assert.Equal(t, 25, result.Payload["age"]) // Converted to int
	assert.Equal(t, "ABC123", result.Payload["external_id"])
	assert.ElementsMatch(t, []string{"name", "age", "external_id"}, result.Decrypted)
	assert.Empty(t, result.Masked)
	assert.Empty(t, result.Denied)
}

func TestSpectatorApplier_AgentMasksPII(t *testing.T) {
	ctx := context.Background()
	decryptor := &mockDecryptor{
		decryptFn: func(ctx context.Context, ct string) (string, error) {
			switch ct {
			case "name-ct":
				return "John Doe", nil
			case "age-ct":
				return "25", nil
			case "external-id-ct":
				return "ABC123", nil
			default:
				return "", nil
			}
		},
	}

	applier := NewSpectatorApplier(decryptor)

	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"name":        types.FieldActionMaskAfterDecrypt,
			"age":         types.FieldActionDecrypt,
			"external_id": types.FieldActionMaskAfterDecrypt,
		},
	}

	row := SpectatorRow{
		ID:           "spectator-1",
		HallID:       "hall-1",
		NameCT:       "name-ct",
		AgeCT:        "age-ct",
		ExternalIDCT: "external-id-ct",
	}

	result, err := applier.Apply(ctx, decision, row)
	require.NoError(t, err)

	assert.Equal(t, "J***", result.Payload["name"])        // Masked string
	assert.Equal(t, 25, result.Payload["age"])             // Decrypted
	assert.Equal(t, "A***", result.Payload["external_id"]) // Masked string
	assert.ElementsMatch(t, []string{"age"}, result.Decrypted)
	assert.ElementsMatch(t, []string{"name", "external_id"}, result.Masked)
	assert.Empty(t, result.Denied)
}

func TestSpectatorApplier_DeveloperMasksAll(t *testing.T) {
	ctx := context.Background()
	decryptor := &mockDecryptor{
		decryptFn: func(ctx context.Context, ct string) (string, error) {
			switch ct {
			case "name-ct":
				return "John Doe", nil
			case "age-ct":
				return "17", nil // Minor
			case "external-id-ct":
				return "ABC123", nil
			default:
				return "", nil
			}
		},
	}

	applier := NewSpectatorApplier(decryptor)

	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"name":        types.FieldActionMaskAfterDecrypt,
			"age":         types.FieldActionMaskAfterDecrypt,
			"external_id": types.FieldActionMaskAfterDecrypt,
		},
	}

	row := SpectatorRow{
		ID:           "spectator-1",
		HallID:       "hall-1",
		NameCT:       "name-ct",
		AgeCT:        "age-ct",
		ExternalIDCT: "external-id-ct",
	}

	result, err := applier.Apply(ctx, decision, row)
	require.NoError(t, err)

	assert.Equal(t, "J***", result.Payload["name"])
	assert.Equal(t, "-18", result.Payload["age"]) // Masked age (minor)
	assert.Equal(t, "A***", result.Payload["external_id"])
	assert.Empty(t, result.Decrypted)
	assert.ElementsMatch(t, []string{"name", "age", "external_id"}, result.Masked)
	assert.Empty(t, result.Denied)
}

func TestSpectatorApplier_DenyFields(t *testing.T) {
	ctx := context.Background()
	decryptor := &mockDecryptor{}

	applier := NewSpectatorApplier(decryptor)

	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"name":        types.FieldActionDeny,
			"age":         types.FieldActionDeny,
			"external_id": types.FieldActionDeny,
		},
	}

	row := SpectatorRow{
		ID:           "spectator-1",
		HallID:       "hall-1",
		NameCT:       "name-ct",
		AgeCT:        "age-ct",
		ExternalIDCT: "external-id-ct",
	}

	result, err := applier.Apply(ctx, decision, row)
	require.NoError(t, err)

	assert.Nil(t, result.Payload["name"])
	assert.Nil(t, result.Payload["age"])
	assert.Nil(t, result.Payload["external_id"])
	assert.Empty(t, result.Decrypted)
	assert.Empty(t, result.Masked)
	assert.ElementsMatch(t, []string{"name", "age", "external_id"}, result.Denied)
}

func TestSpectatorApplier_AgeMaskingAdult(t *testing.T) {
	ctx := context.Background()
	decryptor := &mockDecryptor{
		decryptFn: func(ctx context.Context, ct string) (string, error) {
			if ct == "age-ct" {
				return "35", nil
			}
			return "", nil
		},
	}

	applier := NewSpectatorApplier(decryptor)

	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"age": types.FieldActionMaskAfterDecrypt,
		},
	}

	row := SpectatorRow{
		ID:           "spectator-1",
		HallID:       "hall-1",
		NameCT:       "",
		AgeCT:        "age-ct",
		ExternalIDCT: "",
	}

	result, err := applier.Apply(ctx, decision, row)
	require.NoError(t, err)

	assert.Equal(t, "+18", result.Payload["age"]) // Adult
}
