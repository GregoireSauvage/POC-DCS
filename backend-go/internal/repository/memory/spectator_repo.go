package memory

import (
	"bytes"
	"context"
	"sync"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type SpectatorRepository struct {
	mu         sync.RWMutex
	spectators []*domain.Spectator
}

func NewSpectatorRepository() *SpectatorRepository {
	return &SpectatorRepository{
		spectators: make([]*domain.Spectator, 0),
	}
}

func (r *SpectatorRepository) Create(ctx context.Context, spectator *domain.Spectator) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.spectators = append(r.spectators, spectator)
	return nil
}

func (r *SpectatorRepository) FindByExternalIDLookup(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []*domain.Spectator
	for _, s := range r.spectators {
		if s.TenantID == tenantID && bytes.Equal(s.ExternalIDLookup, lookup) {
			results = append(results, s)
		}
	}
	return results, nil
}

func (r *SpectatorRepository) CountByHall(ctx context.Context, tenantID, hallID string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, s := range r.spectators {
		if s.TenantID == tenantID && s.HallID == hallID {
			count++
		}
	}
	return count, nil
}
