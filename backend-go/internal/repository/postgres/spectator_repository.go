package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgtype"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// SpectatorRepository implements service.SpectatorRepository using PostgreSQL.
type SpectatorRepository struct {
	pool *Pool
}

// NewSpectatorRepository creates a new PostgreSQL spectator repository.
func NewSpectatorRepository(pool *Pool) *SpectatorRepository {
	return &SpectatorRepository{pool: pool}
}

// Create inserts a new spectator.
func (r *SpectatorRepository) Create(ctx context.Context, spectator *domain.Spectator) error {
	if spectator.CreatedAt.IsZero() {
		spectator.CreatedAt = time.Now().UTC()
	}

	var spID pgtype.UUID
	if err := spID.Set(spectator.ID); err != nil {
		return fmt.Errorf("invalid spectator id: %w", err)
	}
	var hallID pgtype.UUID
	if err := hallID.Set(spectator.HallID); err != nil {
		return fmt.Errorf("invalid hall id: %w", err)
	}

	query := `
		INSERT INTO spectators (
			tenant_id, id, hall_id,
			name_ct, age_ct, external_id_ct,
			external_id_lookup, labels, created_at
		) VALUES (
			$1, $2, $3,
			$4, $5, $6,
			$7, $8, $9
		)
	`

	_, err := r.pool.Exec(ctx, query,
		spectator.TenantID,
		spID,
		hallID,
		spectator.NameCT,
		spectator.AgeCT,
		spectator.ExternalIDCT,
		spectator.ExternalIDLookup,
		spectator.Labels,
		spectator.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create spectator: %w", err)
	}
	return nil
}

// FindByExternalIDLookup returns spectators matching the lookup for a tenant.
func (r *SpectatorRepository) FindByExternalIDLookup(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error) {
	query := `
		SELECT tenant_id, id, hall_id,
		       name_ct, age_ct, external_id_ct,
		       external_id_lookup, labels, created_at
		FROM spectators
		WHERE tenant_id = $1 AND external_id_lookup = $2
		ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query, tenantID, lookup)
	if err != nil {
		return nil, fmt.Errorf("failed to query spectators: %w", err)
	}
	defer rows.Close()

	var spectators []*domain.Spectator
	for rows.Next() {
		var sp domain.Spectator
		var id pgtype.UUID
		var hallID pgtype.UUID
		if err := rows.Scan(
			&sp.TenantID,
			&id,
			&hallID,
			&sp.NameCT,
			&sp.AgeCT,
			&sp.ExternalIDCT,
			&sp.ExternalIDLookup,
			&sp.Labels,
			&sp.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan spectator: %w", err)
		}
		if id.Status == pgtype.Present {
			if err := id.AssignTo(&sp.ID); err != nil {
				return nil, fmt.Errorf("failed to parse spectator id: %w", err)
			}
		}
		if hallID.Status == pgtype.Present {
			if err := hallID.AssignTo(&sp.HallID); err != nil {
				return nil, fmt.Errorf("failed to parse hall id: %w", err)
			}
		}
		spectators = append(spectators, &sp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating spectators: %w", err)
	}

	return spectators, nil
}

// CountByHall returns the number of spectators for a hall.
func (r *SpectatorRepository) CountByHall(ctx context.Context, tenantID, hallID string) (int, error) {
	var hallUUID pgtype.UUID
	if err := hallUUID.Set(hallID); err != nil {
		return 0, fmt.Errorf("invalid hall id: %w", err)
	}

	query := `
		SELECT COUNT(*)
		FROM spectators
		WHERE tenant_id = $1 AND hall_id = $2
	`
	var count int
	if err := r.pool.QueryRow(ctx, query, tenantID, hallUUID).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count spectators: %w", err)
	}
	return count, nil
}
