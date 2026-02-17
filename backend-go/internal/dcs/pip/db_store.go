package pip

import (
	"context"
	"fmt"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// ClassificationRepository defines the interface for fetching field classifications from DB
type ClassificationRepository interface {
	GetByResourceType(ctx context.Context, resourceType string) ([]*domain.FieldClassification, error)
}

// DBClassificationStore loads field classifications from the database
type DBClassificationStore struct {
	repo     ClassificationRepository
	fallback ClassificationStore // Fallback to static store if DB fails
}

// NewDBClassificationStore creates a new DB-backed classification store with fallback
func NewDBClassificationStore(repo ClassificationRepository, fallback ClassificationStore) *DBClassificationStore {
	return &DBClassificationStore{
		repo:     repo,
		fallback: fallback,
	}
}

// GetByResourceType implements ClassificationStore interface
func (s *DBClassificationStore) GetByResourceType(ctx context.Context, resourceType string) (map[string]types.Classification, error) {
	// Try to fetch from DB first
	classifications, err := s.repo.GetByResourceType(ctx, resourceType)
	if err != nil {
		// Fallback to static store on error
		if s.fallback != nil {
			return s.fallback.GetByResourceType(ctx, resourceType)
		}
		return nil, fmt.Errorf("db query failed and no fallback available: %w", err)
	}

	// Convert []*domain.FieldClassification to map[string]types.Classification
	result := make(map[string]types.Classification, len(classifications))
	for _, fc := range classifications {
		// Parse classification string to types.Classification
		cls, err := parseClassification(fc.Classification)
		if err != nil {
			// Log warning but continue with other fields
			// TODO: add logger parameter or use context logger
			continue
		}
		result[fc.FieldName] = cls
	}

	// If no results from DB, try fallback
	if len(result) == 0 && s.fallback != nil {
		return s.fallback.GetByResourceType(ctx, resourceType)
	}

	return result, nil
}

// parseClassification converts string classification to types.Classification
func parseClassification(s string) (types.Classification, error) {
	switch s {
	case "PUBLIC":
		return types.ClassificationPublic, nil
	case "INTERNAL":
		return types.ClassificationInternal, nil
	case "SENSITIVE":
		return types.ClassificationSensitive, nil
	case "PII":
		return types.ClassificationPII, nil
	default:
		return "", fmt.Errorf("unknown classification: %s", s)
	}
}
