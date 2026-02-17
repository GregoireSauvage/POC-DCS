package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// TestClassificationRepository_Integration tests against real database
// Set TEST_DATABASE_URL to run this test
func TestClassificationRepository_Integration(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	pool, err := NewPool(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer pool.Close()

	repo := NewClassificationRepository(pool)

	t.Run("GetByResourceType", func(t *testing.T) {
		ctx := context.Background()

		// Fetch film classifications
		films, err := repo.GetByResourceType(ctx, "film")
		if err != nil {
			t.Fatalf("GetByResourceType failed: %v", err)
		}

		// Check we got some results (depends on seed data)
		if len(films) == 0 {
			t.Log("Warning: No film classifications found in database")
		}

		// Verify structure
		for _, fc := range films {
			if fc.ResourceType != "film" {
				t.Errorf("Expected resource_type=film, got %s", fc.ResourceType)
			}
			if fc.FieldName == "" {
				t.Error("field_name should not be empty")
			}
			if fc.Classification == "" {
				t.Error("classification should not be empty")
			}
		}
	})

	t.Run("GetAll", func(t *testing.T) {
		ctx := context.Background()

		all, err := repo.GetAll(ctx)
		if err != nil {
			t.Fatalf("GetAll failed: %v", err)
		}

		if len(all) == 0 {
			t.Log("Warning: No classifications found in database")
		}

		// Verify we have multiple resource types
		resourceTypes := make(map[string]bool)
		for _, fc := range all {
			resourceTypes[fc.ResourceType] = true
		}

		// Should have film, hall, spectator at minimum
		expectedTypes := []string{"film", "hall", "spectator"}
		for _, expected := range expectedTypes {
			if !resourceTypes[expected] {
				t.Logf("Warning: No classifications for resource_type=%s", expected)
			}
		}
	})
}

func TestClassificationRepository_NilPool(t *testing.T) {
	repo := &ClassificationRepository{pool: nil}

	ctx := context.Background()

	_, err := repo.GetByResourceType(ctx, "film")
	if err == nil {
		t.Error("Expected error when pool is nil")
	}

	_, err = repo.GetAll(ctx)
	if err == nil {
		t.Error("Expected error when pool is nil")
	}
}

// MockClassificationData creates test data matching the domain model
func MockClassificationData() []*domain.FieldClassification {
	return []*domain.FieldClassification{
		{ResourceType: "film", FieldName: "title", Classification: "PUBLIC"},
		{ResourceType: "film", FieldName: "time_elapsed", Classification: "SENSITIVE"},
		{ResourceType: "hall", FieldName: "name", Classification: "PUBLIC"},
		{ResourceType: "hall", FieldName: "owner_user_id", Classification: "INTERNAL"},
		{ResourceType: "hall", FieldName: "current_film_id", Classification: "INTERNAL"},
		{ResourceType: "spectator", FieldName: "name", Classification: "PII"},
		{ResourceType: "spectator", FieldName: "age", Classification: "SENSITIVE"},
		{ResourceType: "spectator", FieldName: "external_id", Classification: "PII"},
	}
}
