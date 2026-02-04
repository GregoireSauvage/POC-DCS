package pip

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type StaticClassificationStore struct {
	ByResource map[string]map[string]types.Classification
}

func (s *StaticClassificationStore) GetByResourceType(_ context.Context, resourceType string) (map[string]types.Classification, error) {
	fields := s.ByResource[resourceType]
	out := make(map[string]types.Classification, len(fields))
	for k, v := range fields {
		out[k] = v
	}
	return out, nil
}
