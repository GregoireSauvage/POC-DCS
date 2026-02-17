package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

func TestHallRepository_CRUD(t *testing.T) {
	pool := getTestPool(t)
	truncateTables(t, pool, "spectators", "halls", "films", "users")

	tenantID := "t1"
	userID := uuid.New()
	filmID := uuid.New()
	hallID := uuid.New()

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

	repo := NewHallRepository(pool)
	err = repo.Create(context.Background(), &domain.Hall{
		TenantID:      tenantID,
		ID:            hallID.String(),
		Name:          "Hall A",
		OwnerUserID:   userID.String(),
		CurrentFilmID: filmID.String(),
	})
	require.NoError(t, err)

	list, err := repo.ListByTenant(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, hallID.String(), list[0].ID)

	got, err := repo.FindByID(context.Background(), tenantID, hallID.String())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, hallID.String(), got.ID)

	count, err := repo.CountSpectators(context.Background(), tenantID, hallID.String())
	require.NoError(t, err)
	require.Equal(t, 0, count)

	_, err = pool.Exec(context.Background(), `
		INSERT INTO spectators (
			tenant_id, id, hall_id, name_ct, age_ct, external_id_ct, external_id_lookup, labels
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, '[]'::jsonb
		)
	`, tenantID, uuid.New(), hallID, "ct", "ct", "ct", []byte{1, 2, 3})
	require.NoError(t, err)

	count, err = repo.CountSpectators(context.Background(), tenantID, hallID.String())
	require.NoError(t, err)
	require.Equal(t, 1, count)
}
