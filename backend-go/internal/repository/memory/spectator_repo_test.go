package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

func TestSpectatorRepository_Create(t *testing.T) {
	ctx := context.Background()
	repo := NewSpectatorRepository()

	spectator := &domain.Spectator{
		TenantID:         "t1",
		ID:               "spectator-1",
		HallID:           "hall-1",
		NameCT:           "vault:v1:encrypted-name",
		AgeCT:            "vault:v1:encrypted-age",
		ExternalIDCT:     "vault:v1:encrypted-id",
		ExternalIDLookup: []byte("hmac-lookup"),
	}

	err := repo.Create(ctx, spectator)
	require.NoError(t, err)

	// Verify stored
	results, err := repo.FindByExternalIDLookup(ctx, "t1", []byte("hmac-lookup"))
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "spectator-1", results[0].ID)
}

func TestSpectatorRepository_FindByExternalIDLookup_NotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewSpectatorRepository()

	results, err := repo.FindByExternalIDLookup(ctx, "t1", []byte("nonexistent"))
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestSpectatorRepository_FindByExternalIDLookup_MultipleMatches(t *testing.T) {
	ctx := context.Background()
	repo := NewSpectatorRepository()

	lookup := []byte("same-lookup")
	spectator1 := &domain.Spectator{
		TenantID:         "t1",
		ID:               "spectator-1",
		HallID:           "hall-1",
		NameCT:           "vault:v1:encrypted-name1",
		AgeCT:            "vault:v1:encrypted-age1",
		ExternalIDCT:     "vault:v1:encrypted-id1",
		ExternalIDLookup: lookup,
	}
	spectator2 := &domain.Spectator{
		TenantID:         "t1",
		ID:               "spectator-2",
		HallID:           "hall-2",
		NameCT:           "vault:v1:encrypted-name2",
		AgeCT:            "vault:v1:encrypted-age2",
		ExternalIDCT:     "vault:v1:encrypted-id2",
		ExternalIDLookup: lookup,
	}

	require.NoError(t, repo.Create(ctx, spectator1))
	require.NoError(t, repo.Create(ctx, spectator2))

	results, err := repo.FindByExternalIDLookup(ctx, "t1", lookup)
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestSpectatorRepository_FindByExternalIDLookup_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	repo := NewSpectatorRepository()

	lookup := []byte("same-lookup")
	spectator1 := &domain.Spectator{
		TenantID:         "t1",
		ID:               "spectator-1",
		HallID:           "hall-1",
		NameCT:           "vault:v1:encrypted-name1",
		AgeCT:            "vault:v1:encrypted-age1",
		ExternalIDCT:     "vault:v1:encrypted-id1",
		ExternalIDLookup: lookup,
	}
	spectator2 := &domain.Spectator{
		TenantID:         "t2",
		ID:               "spectator-2",
		HallID:           "hall-2",
		NameCT:           "vault:v1:encrypted-name2",
		AgeCT:            "vault:v1:encrypted-age2",
		ExternalIDCT:     "vault:v1:encrypted-id2",
		ExternalIDLookup: lookup,
	}

	require.NoError(t, repo.Create(ctx, spectator1))
	require.NoError(t, repo.Create(ctx, spectator2))

	// Should only return t1 spectator
	results, err := repo.FindByExternalIDLookup(ctx, "t1", lookup)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "spectator-1", results[0].ID)
}

func TestSpectatorRepository_CountByHall(t *testing.T) {
	ctx := context.Background()
	repo := NewSpectatorRepository()

	spectator1 := &domain.Spectator{
		TenantID:         "t1",
		ID:               "spectator-1",
		HallID:           "hall-1",
		NameCT:           "vault:v1:encrypted-name1",
		AgeCT:            "vault:v1:encrypted-age1",
		ExternalIDCT:     "vault:v1:encrypted-id1",
		ExternalIDLookup: []byte("lookup-1"),
	}
	spectator2 := &domain.Spectator{
		TenantID:         "t1",
		ID:               "spectator-2",
		HallID:           "hall-1",
		NameCT:           "vault:v1:encrypted-name2",
		AgeCT:            "vault:v1:encrypted-age2",
		ExternalIDCT:     "vault:v1:encrypted-id2",
		ExternalIDLookup: []byte("lookup-2"),
	}
	spectator3 := &domain.Spectator{
		TenantID:         "t1",
		ID:               "spectator-3",
		HallID:           "hall-2",
		NameCT:           "vault:v1:encrypted-name3",
		AgeCT:            "vault:v1:encrypted-age3",
		ExternalIDCT:     "vault:v1:encrypted-id3",
		ExternalIDLookup: []byte("lookup-3"),
	}

	require.NoError(t, repo.Create(ctx, spectator1))
	require.NoError(t, repo.Create(ctx, spectator2))
	require.NoError(t, repo.Create(ctx, spectator3))

	count, err := repo.CountByHall(ctx, "t1", "hall-1")
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	count, err = repo.CountByHall(ctx, "t1", "hall-2")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestSpectatorRepository_CountByHall_Empty(t *testing.T) {
	ctx := context.Background()
	repo := NewSpectatorRepository()

	count, err := repo.CountByHall(ctx, "t1", "nonexistent-hall")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
