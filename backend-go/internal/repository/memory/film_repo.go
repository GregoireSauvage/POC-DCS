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

func (r *FilmRepository) Create(_ context.Context, tenantID, title, timeElapsedCT string) (service.FilmRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate a simple ID for in-memory repository
	id := generateID()
	record := service.FilmRecord{
		ID:            id,
		TenantID:      tenantID,
		Title:         title,
		TimeElapsedCT: timeElapsedCT,
	}
	r.films = append(r.films, record)
	return record, nil
}

// generateID creates a simple ID for in-memory storage (not production-ready)
func generateID() string {
	return "film-" + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[i%len(letters)]
	}
	return string(b)
}
