package spif

import (
	"context"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func TestStaticProvider_Current(t *testing.T) {
	provider := NewStaticProvider(config.PolicyConfig{
		PolicyID:            "cinema-default",
		PolicyVersion:       "v1",
		ClassificationOrder: []service.Classification{service.ClassificationPublic, service.ClassificationInternal},
		AllowedCategories:   []string{"ops"},
		Markings:            map[string]string{"PUBLIC": "U"},
	})

	policy, err := provider.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if policy.PolicyID != "cinema-default" || policy.PolicyVersion != "v1" {
		t.Fatalf("unexpected policy %+v", policy)
	}
}
