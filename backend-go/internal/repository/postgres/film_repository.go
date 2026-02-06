package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// FilmRepository implements service.FilmRepository using PostgreSQL
type FilmRepository struct {
	pool *Pool
}

// NewFilmRepository creates a new PostgreSQL film repository
func NewFilmRepository(pool *Pool) *FilmRepository {
	return &FilmRepository{pool: pool}
}

// ListByTenant returns all films for a given tenant
func (r *FilmRepository) ListByTenant(ctx context.Context, tenantID string) ([]service.FilmRecord, error) {
	query := `
		SELECT id, tenant_id, title, time_elapsed_ct
		FROM films
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query films: %w", err)
	}
	defer rows.Close()

	var films []service.FilmRecord
	for rows.Next() {
		var record service.FilmRecord
		if err := rows.Scan(&record.ID, &record.TenantID, &record.Title, &record.TimeElapsedCT); err != nil {
			return nil, fmt.Errorf("failed to scan film: %w", err)
		}
		films = append(films, record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating films: %w", err)
	}

	return films, nil
}

// GetByID returns a single film by ID and tenant (helper method, not in interface)
func (r *FilmRepository) GetByID(ctx context.Context, tenantID, filmID string) (*domain.Film, error) {
	query := `
		SELECT id, tenant_id, title, time_elapsed_ct, labels, created_at
		FROM films
		WHERE tenant_id = $1 AND id = $2
	`

	row := r.pool.QueryRow(ctx, query, tenantID, filmID)

	film, err := scanFilmRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.New("film not found")
		}
		return nil, fmt.Errorf("failed to get film: %w", err)
	}

	return film, nil
}

// Create inserts a new film
func (r *FilmRepository) Create(ctx context.Context, film *domain.Film) error {
	if film.CreatedAt.IsZero() {
		film.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO films (id, tenant_id, title, time_elapsed_ct, labels, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.pool.Exec(ctx, query,
		film.ID,
		film.TenantID,
		film.Title,
		film.TimeElapsedCT,
		film.Labels,
		film.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create film: %w", err)
	}

	return nil
}

// UpdateTimeCiphertext updates the encrypted time_elapsed field
func (r *FilmRepository) UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (service.FilmRecord, error) {
	query := `
		UPDATE films
		SET time_elapsed_ct = $1
		WHERE tenant_id = $2 AND id = $3
		RETURNING id, tenant_id, title, time_elapsed_ct
	`

	var record service.FilmRecord
	err := r.pool.QueryRow(ctx, query, ciphertext, tenantID, filmID).Scan(
		&record.ID,
		&record.TenantID,
		&record.Title,
		&record.TimeElapsedCT,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return service.FilmRecord{}, errors.New("film not found")
		}
		return service.FilmRecord{}, fmt.Errorf("failed to update film time: %w", err)
	}

	return record, nil
}

// scanFilm scans a film from pgx.Rows
func scanFilm(rows pgx.Rows) (*domain.Film, error) {
	var film domain.Film
	err := rows.Scan(
		&film.ID,
		&film.TenantID,
		&film.Title,
		&film.TimeElapsedCT,
		&film.Labels,
		&film.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &film, nil
}

// scanFilmRow scans a film from pgx.Row
func scanFilmRow(row pgx.Row) (*domain.Film, error) {
	var film domain.Film
	err := row.Scan(
		&film.ID,
		&film.TenantID,
		&film.Title,
		&film.TimeElapsedCT,
		&film.Labels,
		&film.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &film, nil
}
