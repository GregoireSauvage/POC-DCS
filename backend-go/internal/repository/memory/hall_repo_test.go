package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

func TestHallRepository_FindByID_Found(t *testing.T) {
	ctx := context.Background()
	halls := []domain.Hall{
		{
			TenantID:      "t1",
			ID:            "hall-1",
			Name:          "IMAX Theater",
			OwnerUserID:   "user-1",
			CurrentFilmID: "film-1",
		},
		{
			TenantID:      "t1",
			ID:            "hall-2",
			Name:          "Standard Screen",
			OwnerUserID:   "user-2",
			CurrentFilmID: "film-2",
		},
	}
	repo := NewHallRepository(halls)

	hall, err := repo.FindByID(ctx, "t1", "hall-1")
	require.NoError(t, err)
	require.NotNil(t, hall)
	assert.Equal(t, "hall-1", hall.ID)
	assert.Equal(t, "t1", hall.TenantID)
	assert.Equal(t, "IMAX Theater", hall.Name)
	assert.Equal(t, "user-1", hall.OwnerUserID)
	assert.Equal(t, "film-1", hall.CurrentFilmID)
}

func TestHallRepository_FindByID_NotFound(t *testing.T) {
	ctx := context.Background()
	halls := []domain.Hall{
		{
			TenantID:      "t1",
			ID:            "hall-1",
			Name:          "IMAX Theater",
			OwnerUserID:   "user-1",
			CurrentFilmID: "film-1",
		},
	}
	repo := NewHallRepository(halls)

	hall, err := repo.FindByID(ctx, "t1", "nonexistent-hall")
	require.NoError(t, err)
	assert.Nil(t, hall, "Should return nil when hall doesn't exist")
}

func TestHallRepository_FindByID_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	halls := []domain.Hall{
		{
			TenantID:      "t1",
			ID:            "hall-1",
			Name:          "IMAX Theater",
			OwnerUserID:   "user-1",
			CurrentFilmID: "film-1",
		},
		{
			TenantID:      "t2",
			ID:            "hall-1", // Same ID but different tenant
			Name:          "Another Theater",
			OwnerUserID:   "user-2",
			CurrentFilmID: "film-2",
		},
	}
	repo := NewHallRepository(halls)

	// t1 should only find its own hall
	hall, err := repo.FindByID(ctx, "t1", "hall-1")
	require.NoError(t, err)
	require.NotNil(t, hall)
	assert.Equal(t, "t1", hall.TenantID)
	assert.Equal(t, "IMAX Theater", hall.Name)

	// t2 should find its own hall with same ID
	hall, err = repo.FindByID(ctx, "t2", "hall-1")
	require.NoError(t, err)
	require.NotNil(t, hall)
	assert.Equal(t, "t2", hall.TenantID)
	assert.Equal(t, "Another Theater", hall.Name)

	// t3 (different tenant) should not find hall-1
	hall, err = repo.FindByID(ctx, "t3", "hall-1")
	require.NoError(t, err)
	assert.Nil(t, hall, "Should not find hall from different tenant")
}

func TestHallRepository_FindByID_EmptyRepository(t *testing.T) {
	ctx := context.Background()
	repo := NewHallRepository([]domain.Hall{})

	hall, err := repo.FindByID(ctx, "t1", "hall-1")
	require.NoError(t, err)
	assert.Nil(t, hall, "Should return nil when repository is empty")
}
