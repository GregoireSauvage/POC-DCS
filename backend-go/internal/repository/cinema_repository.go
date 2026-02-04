package repository

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type CinemaRepository interface {
	ListFilms(ctx context.Context, tenantID string) ([]domain.Film, error)
	CreateFilm(ctx context.Context, film domain.Film) (domain.Film, error)
	UpdateFilmTime(ctx context.Context, tenantID, filmID, timeElapsedCT string) (domain.Film, error)

	ListHalls(ctx context.Context, tenantID string) ([]domain.Hall, error)
	CreateHall(ctx context.Context, hall domain.Hall) (domain.Hall, error)

	CreateSpectator(ctx context.Context, spectator domain.Spectator) (domain.Spectator, error)
	FindSpectatorsByLookup(ctx context.Context, tenantID string, lookup []byte) ([]domain.Spectator, error)
}
