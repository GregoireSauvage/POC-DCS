package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

func TestSpectatorRepository_CRUD(t *testing.T) {
	pool := getTestPool(t)
	truncateTables(t, pool, "spectators", "halls", "films", "users")

	tenantID := "t1"
	userID := uuid.New()
	filmID := uuid.New()
	hallID := uuid.New()
	spectatorID := uuid.New()

	_, err := pool.Exec(context.Background(), `
		INSERT INTO users (tenant_id, id, username, role, password_hash, labels)
		VALUES ($1, $2, $3, $4, $5, '[]'::jsonb)
	`, tenantID, userID, "admin", "admin", "hash")
	require.NoError(t, err)

	_, err = pool.Exec(context.Background(), `
		INSERT INTO films (tenant_id, id, title, time_elapsed_ct, labels)
		VALUES ($1, $2, $3, $4, '[]'::jsonb)
	`, tenantID, filmID, "Interstellar", "vault:v1:test")
	require.NoError(t, err)

	_, err = pool.Exec(context.Background(), `
		INSERT INTO halls (tenant_id, id, name, owner_user_id, current_film_id, labels)
		VALUES ($1, $2, $3, $4, $5, '[]'::jsonb)
	`, tenantID, hallID, "Hall A", userID, filmID)
	require.NoError(t, err)

	repo := NewSpectatorRepository(pool)
	lookup := []byte{9, 9, 9}
	err = repo.Create(context.Background(), &domain.Spectator{
		TenantID:         tenantID,
		ID:               spectatorID.String(),
		HallID:           hallID.String(),
		NameCT:           "ct",
		AgeCT:            "ct",
		ExternalIDCT:     "ct",
		ExternalIDLookup: lookup,
	})
	require.NoError(t, err)

	results, err := repo.FindByExternalIDLookup(context.Background(), tenantID, lookup)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, spectatorID.String(), results[0].ID)

	count, err := repo.CountByHall(context.Background(), tenantID, hallID.String())
	require.NoError(t, err)
	require.Equal(t, 1, count)
}
