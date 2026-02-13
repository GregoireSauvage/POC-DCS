package memory

import (
	"context"
	"sync"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// HallRepository is an in-memory implementation for testing
type HallRepository struct {
	mu    sync.RWMutex
	halls []domain.Hall
	// Map of hall_id -> spectator count (for testing)
	spectatorCounts map[string]int
}

// NewHallRepository creates an in-memory hall repository
func NewHallRepository(halls []domain.Hall) *HallRepository {
	return &HallRepository{
		halls:           halls,
		spectatorCounts: make(map[string]int),
	}
}

// ListByTenant returns all halls for a tenant
func (r *HallRepository) ListByTenant(ctx context.Context, tenantID string) ([]service.HallRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []service.HallRecord
	for _, h := range r.halls {
		if h.TenantID == tenantID {
			result = append(result, service.HallRecord{
				TenantID:      h.TenantID,
				ID:            h.ID,
				Name:          h.Name,
				OwnerUserID:   h.OwnerUserID,
				CurrentFilmID: h.CurrentFilmID,
			})
		}
	}
	return result, nil
}

// Create adds a new hall
func (r *HallRepository) Create(ctx context.Context, hall *domain.Hall) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.halls = append(r.halls, *hall)
	r.spectatorCounts[hall.ID] = 0 // New hall has no spectators
	return nil
}

// CountSpectators returns the number of spectators in a hall
func (r *HallRepository) CountSpectators(ctx context.Context, tenantID string, hallID string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return mock count if set, otherwise 0
	if count, ok := r.spectatorCounts[hallID]; ok {
		return count, nil
	}
	return 0, nil
}

// SetSpectatorCount sets a mock spectator count (for testing)
func (r *HallRepository) SetSpectatorCount(hallID string, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spectatorCounts[hallID] = count
}
