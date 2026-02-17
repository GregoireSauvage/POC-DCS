package postgres

import (
	"context"
	"fmt"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type ClassificationRepository struct {
	pool *Pool
}

func NewClassificationRepository(pool *Pool) *ClassificationRepository {
	return &ClassificationRepository{pool: pool}
}

// GetByResourceType fetches all field classifications for a given resource type
func (r *ClassificationRepository) GetByResourceType(ctx context.Context, resourceType string) ([]*domain.FieldClassification, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("database pool not available")
	}

	query := `
		SELECT resource_type, field_name, classification
		FROM field_classification
		WHERE resource_type = $1
		ORDER BY field_name
	`

	rows, err := r.pool.Query(ctx, query, resourceType)
	if err != nil {
		return nil, fmt.Errorf("query field_classification: %w", err)
	}
	defer rows.Close()

	var results []*domain.FieldClassification
	for rows.Next() {
		var fc domain.FieldClassification
		if err := rows.Scan(&fc.ResourceType, &fc.FieldName, &fc.Classification); err != nil {
			return nil, fmt.Errorf("scan field_classification: %w", err)
		}
		results = append(results, &fc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return results, nil
}

// GetAll fetches all field classifications from the database
func (r *ClassificationRepository) GetAll(ctx context.Context) ([]*domain.FieldClassification, error) {
	if r.pool == nil {
		return nil, fmt.Errorf("database pool not available")
	}

	query := `
		SELECT resource_type, field_name, classification
		FROM field_classification
		ORDER BY resource_type, field_name
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query field_classification: %w", err)
	}
	defer rows.Close()

	var results []*domain.FieldClassification
	for rows.Next() {
		var fc domain.FieldClassification
		if err := rows.Scan(&fc.ResourceType, &fc.FieldName, &fc.Classification); err != nil {
			return nil, fmt.Errorf("scan field_classification: %w", err)
		}
		results = append(results, &fc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return results, nil
}
