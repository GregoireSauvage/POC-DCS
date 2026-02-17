package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// HallRepository implements service.HallRepository using PostgreSQL.
type HallRepository struct {
	pool *Pool
}

// NewHallRepository creates a new PostgreSQL hall repository.
func NewHallRepository(pool *Pool) *HallRepository {
	return &HallRepository{pool: pool}
}

// ListByTenant returns all halls for a tenant.
func (r *HallRepository) ListByTenant(ctx context.Context, tenantID string) ([]service.HallRecord, error) {
	query := `
		SELECT id, tenant_id, name, owner_user_id, current_film_id
		FROM halls
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query halls: %w", err)
	}
	defer rows.Close()

	var halls []service.HallRecord
	for rows.Next() {
		var record service.HallRecord
		var id pgtype.UUID
		var ownerID pgtype.UUID
		var filmID pgtype.UUID
		if err := rows.Scan(&id, &record.TenantID, &record.Name, &ownerID, &filmID); err != nil {
			return nil, fmt.Errorf("failed to scan hall: %w", err)
		}
		if id.Status == pgtype.Present {
			if err := id.AssignTo(&record.ID); err != nil {
				return nil, fmt.Errorf("failed to parse hall id: %w", err)
			}
		}
		if ownerID.Status == pgtype.Present {
			if err := ownerID.AssignTo(&record.OwnerUserID); err != nil {
				return nil, fmt.Errorf("failed to parse owner_user_id: %w", err)
			}
		}
		if filmID.Status == pgtype.Present {
			if err := filmID.AssignTo(&record.CurrentFilmID); err != nil {
				return nil, fmt.Errorf("failed to parse current_film_id: %w", err)
			}
		}
		halls = append(halls, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating halls: %w", err)
	}

	return halls, nil
}

// Create inserts a new hall.
func (r *HallRepository) Create(ctx context.Context, hall *domain.Hall) error {
	if hall.CreatedAt.IsZero() {
		hall.CreatedAt = time.Now().UTC()
	}

	var hallID pgtype.UUID
	if err := hallID.Set(hall.ID); err != nil {
		return fmt.Errorf("invalid hall id: %w", err)
	}
	var ownerID pgtype.UUID
	if err := ownerID.Set(hall.OwnerUserID); err != nil {
		return fmt.Errorf("invalid owner_user_id: %w", err)
	}
	var filmID pgtype.UUID
	if err := filmID.Set(hall.CurrentFilmID); err != nil {
		return fmt.Errorf("invalid current_film_id: %w", err)
	}

	query := `
		INSERT INTO halls (tenant_id, id, name, owner_user_id, current_film_id, labels, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.pool.Exec(ctx, query,
		hall.TenantID,
		hallID,
		hall.Name,
		ownerID,
		filmID,
		hall.Labels,
		hall.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create hall: %w", err)
	}
	return nil
}

// CountSpectators returns the number of spectators in a hall.
func (r *HallRepository) CountSpectators(ctx context.Context, tenantID string, hallID string) (int, error) {
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

// FindByID returns a hall by tenant and id.
func (r *HallRepository) FindByID(ctx context.Context, tenantID string, hallID string) (*domain.Hall, error) {
	var hallUUID pgtype.UUID
	if err := hallUUID.Set(hallID); err != nil {
		return nil, fmt.Errorf("invalid hall id: %w", err)
	}

	query := `
		SELECT id, tenant_id, name, owner_user_id, current_film_id, labels, created_at
		FROM halls
		WHERE tenant_id = $1 AND id = $2
	`
	row := r.pool.QueryRow(ctx, query, tenantID, hallUUID)

	var hall domain.Hall
	var id pgtype.UUID
	var ownerID pgtype.UUID
	var filmID pgtype.UUID

	if err := row.Scan(
		&id,
		&hall.TenantID,
		&hall.Name,
		&ownerID,
		&filmID,
		&hall.Labels,
		&hall.CreatedAt,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get hall: %w", err)
	}

	if id.Status == pgtype.Present {
		if err := id.AssignTo(&hall.ID); err != nil {
			return nil, fmt.Errorf("failed to parse hall id: %w", err)
		}
	}
	if ownerID.Status == pgtype.Present {
		if err := ownerID.AssignTo(&hall.OwnerUserID); err != nil {
			return nil, fmt.Errorf("failed to parse owner_user_id: %w", err)
		}
	}
	if filmID.Status == pgtype.Present {
		if err := filmID.AssignTo(&hall.CurrentFilmID); err != nil {
			return nil, fmt.Errorf("failed to parse current_film_id: %w", err)
		}
	}

	return &hall, nil
}
