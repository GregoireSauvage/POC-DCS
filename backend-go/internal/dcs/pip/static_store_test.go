package pip

import (
	"context"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func TestStaticClassificationStore_GetByResourceType(t *testing.T) {
	tests := []struct {
		name         string
		store        *StaticClassificationStore
		resourceType string
		wantLen      int
		wantFields   map[string]types.Classification
	}{
		{
			name: "existing resource with multiple fields",
			store: &StaticClassificationStore{
				ByResource: map[string]map[string]types.Classification{
					"film": {
						"title":        types.ClassificationPublic,
						"time_elapsed": types.ClassificationSensitive,
						"budget":       types.ClassificationPII,
					},
				},
			},
			resourceType: "film",
			wantLen:      3,
			wantFields: map[string]types.Classification{
				"title":        types.ClassificationPublic,
				"time_elapsed": types.ClassificationSensitive,
				"budget":       types.ClassificationPII,
			},
		},
		{
			name: "nonexistent resource type returns empty map",
			store: &StaticClassificationStore{
				ByResource: map[string]map[string]types.Classification{
					"film": {
						"title": types.ClassificationPublic,
					},
				},
			},
			resourceType: "hall",
			wantLen:      0,
			wantFields:   map[string]types.Classification{},
		},
		{
			name: "empty store returns empty map",
			store: &StaticClassificationStore{
				ByResource: map[string]map[string]types.Classification{},
			},
			resourceType: "film",
			wantLen:      0,
			wantFields:   map[string]types.Classification{},
		},
		{
			name: "nil ByResource map returns empty map",
			store: &StaticClassificationStore{
				ByResource: nil,
			},
			resourceType: "film",
			wantLen:      0,
			wantFields:   map[string]types.Classification{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			got, err := tt.store.GetByResourceType(ctx, tt.resourceType)

			if err != nil {
				t.Fatalf("GetByResourceType() error = %v, want nil", err)
			}

			if len(got) != tt.wantLen {
				t.Errorf("GetByResourceType() returned %d fields, want %d", len(got), tt.wantLen)
			}

			for field, wantClass := range tt.wantFields {
				gotClass, ok := got[field]
				if !ok {
					t.Errorf("field %q missing from result", field)
					continue
				}
				if gotClass != wantClass {
					t.Errorf("field %q classification = %v, want %v", field, gotClass, wantClass)
				}
			}
		})
	}
}

func TestStaticClassificationStore_ReturnsCopy(t *testing.T) {
	store := &StaticClassificationStore{
		ByResource: map[string]map[string]types.Classification{
			"film": {
				"title": types.ClassificationPublic,
			},
		},
	}

	ctx := context.Background()

	// Get classification map twice
	result1, err := store.GetByResourceType(ctx, "film")
	if err != nil {
		t.Fatalf("GetByResourceType() error = %v", err)
	}

	result2, err := store.GetByResourceType(ctx, "film")
	if err != nil {
		t.Fatalf("GetByResourceType() error = %v", err)
	}

	// Modify first result
	result1["new_field"] = types.ClassificationSensitive

	// Second result should not be affected
	if _, exists := result2["new_field"]; exists {
		t.Error("modifying returned map affected subsequent calls - not returning a copy")
	}

	// Original store should not be affected
	if _, exists := store.ByResource["film"]["new_field"]; exists {
		t.Error("modifying returned map affected original store - not returning a copy")
	}
}
