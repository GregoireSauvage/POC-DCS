package pip

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type fakeClassificationRepo struct {
	data []*domain.FieldClassification
	err  error
}

func (f *fakeClassificationRepo) GetByResourceType(ctx context.Context, resourceType string) ([]*domain.FieldClassification, error) {
	if f.err != nil {
		return nil, f.err
	}
	var result []*domain.FieldClassification
	for _, fc := range f.data {
		if fc.ResourceType == resourceType {
			result = append(result, fc)
		}
	}
	return result, nil
}

func TestDBClassificationStore_GetByResourceType_Success(t *testing.T) {
	repo := &fakeClassificationRepo{
		data: []*domain.FieldClassification{
			{ResourceType: "film", FieldName: "title", Classification: "PUBLIC"},
			{ResourceType: "film", FieldName: "time_elapsed", Classification: "SENSITIVE"},
			{ResourceType: "hall", FieldName: "name", Classification: "PUBLIC"},
		},
	}

	store := NewDBClassificationStore(repo, nil)

	result, err := store.GetByResourceType(context.Background(), "film")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected 2 fields, got %d", len(result))
	}

	if result["title"] != types.ClassificationPublic {
		t.Errorf("Expected title=PUBLIC, got %s", result["title"])
	}

	if result["time_elapsed"] != types.ClassificationSensitive {
		t.Errorf("Expected time_elapsed=SENSITIVE, got %s", result["time_elapsed"])
	}
}

func TestDBClassificationStore_GetByResourceType_Fallback(t *testing.T) {
	// DB returns error
	repo := &fakeClassificationRepo{
		err: errors.New("db connection failed"),
	}

	// Static fallback store
	fallback := &StaticClassificationStore{
		ByResource: map[string]map[string]types.Classification{
			"film": {
				"title": types.ClassificationPublic,
			},
		},
	}

	store := NewDBClassificationStore(repo, fallback)

	result, err := store.GetByResourceType(context.Background(), "film")
	if err != nil {
		t.Fatalf("Expected no error with fallback, got: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 field from fallback, got %d", len(result))
	}

	if result["title"] != types.ClassificationPublic {
		t.Errorf("Expected title=PUBLIC from fallback, got %s", result["title"])
	}
}

func TestDBClassificationStore_GetByResourceType_NoFallback(t *testing.T) {
	repo := &fakeClassificationRepo{
		err: errors.New("db connection failed"),
	}

	store := NewDBClassificationStore(repo, nil) // No fallback

	_, err := store.GetByResourceType(context.Background(), "film")
	if err == nil {
		t.Fatal("Expected error when DB fails and no fallback")
	}

	if err.Error() != "db query failed and no fallback available: db connection failed" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestDBClassificationStore_GetByResourceType_EmptyResultUseFallback(t *testing.T) {
	// DB returns no results
	repo := &fakeClassificationRepo{
		data: []*domain.FieldClassification{},
	}

	fallback := &StaticClassificationStore{
		ByResource: map[string]map[string]types.Classification{
			"unknown": {
				"field1": types.ClassificationPublic,
			},
		},
	}

	store := NewDBClassificationStore(repo, fallback)

	result, err := store.GetByResourceType(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 field from fallback, got %d", len(result))
	}
}

func TestParseClassification(t *testing.T) {
	tests := []struct {
		input    string
		expected types.Classification
		wantErr  bool
	}{
		{"PUBLIC", types.ClassificationPublic, false},
		{"INTERNAL", types.ClassificationInternal, false},
		{"SENSITIVE", types.ClassificationSensitive, false},
		{"PII", types.ClassificationPII, false},
		{"UNKNOWN", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseClassification(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for input %q", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

func TestDBClassificationStore_GetByResourceType_InvalidClassification(t *testing.T) {
	repo := &fakeClassificationRepo{
		data: []*domain.FieldClassification{
			{ResourceType: "film", FieldName: "title", Classification: "PUBLIC"},
			{ResourceType: "film", FieldName: "bad_field", Classification: "INVALID"}, // Invalid
			{ResourceType: "film", FieldName: "time_elapsed", Classification: "SENSITIVE"},
		},
	}

	store := NewDBClassificationStore(repo, nil)

	result, err := store.GetByResourceType(context.Background(), "film")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should skip invalid classification and return only valid ones
	if len(result) != 2 {
		t.Fatalf("Expected 2 valid fields, got %d", len(result))
	}

	if _, ok := result["bad_field"]; ok {
		t.Error("Expected bad_field to be skipped")
	}
}
