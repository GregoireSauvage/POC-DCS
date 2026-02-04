package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type FilmRepository struct {
	mu    sync.RWMutex
	films []service.FilmRecord
}

func NewFilmRepository(seed []service.FilmRecord) *FilmRepository {
	items := make([]service.FilmRecord, len(seed))
	copy(items, seed)
	return &FilmRepository{films: items}
}

func (r *FilmRepository) ListByTenant(_ context.Context, tenantID string) ([]service.FilmRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]service.FilmRecord, 0, len(r.films))
	for _, film := range r.films {
		if film.TenantID == tenantID {
			out = append(out, film)
		}
	}
	return out, nil
}

func (r *FilmRepository) UpdateTimeCiphertext(_ context.Context, tenantID, filmID, ciphertext string) (service.FilmRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range r.films {
		if r.films[i].TenantID == tenantID && r.films[i].ID == filmID {
			r.films[i].TimeElapsedCT = ciphertext
			return r.films[i], nil
		}
	}
	return service.FilmRecord{}, errors.New("film not found")
}
