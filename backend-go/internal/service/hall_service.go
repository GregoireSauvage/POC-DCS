package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

type hallService struct {
	repo     HallRepository
	enforcer PolicyEnforcer
	audit    *AuditService
}

// NewHallService creates a new hall service
func NewHallService(repo HallRepository, enforcer PolicyEnforcer, audit *AuditService) HallService {
	return &hallService{
		repo:     repo,
		enforcer: enforcer,
		audit:    audit,
	}
}

// List returns all halls for the tenant with field-level enforcement
func (s *hallService) List(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) ([]HallOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	// 1. Fetch halls from repository
	stop := perf.Span(ctx, "db_ms")
	records, err := s.repo.ListByTenant(ctx, principal.TenantID)
	stop()
	if err != nil {
		return nil, pctx, fmt.Errorf("failed to list halls: %w", err)
	}

	// 2. Apply field-level enforcement to each hall
	outputs := make([]HallOutput, 0, len(records))
	for _, rec := range records {
		// Enforce read policy
		result, err := s.enforcer.EnforceHallRead(ctx, principal, reqCtx, HallReadInput{
			HallID:        rec.ID,
			Name:          rec.Name,
			OwnerUserID:   rec.OwnerUserID,
			CurrentFilmID: rec.CurrentFilmID,
		})
		if err != nil {
			return nil, pctx, fmt.Errorf("failed to enforce hall read: %w", err)
		}

		// 3. Compute spectator count
		spectatorCount, _ := s.repo.CountSpectators(ctx, principal.TenantID, rec.ID)

		outputs = append(outputs, HallOutput{
			ID:             rec.ID,
			Name:           result.Name,
			OwnerUserID:    result.OwnerUserID,
			CurrentFilmID:  result.CurrentFilmID,
			SpectatorCount: spectatorCount,
		})
	}

	return outputs, pctx, nil
}

// Create creates a new hall
func (s *hallService) Create(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	input HallCreateInput,
) (HallOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	// 1. Authorization check
	decision, err := s.enforcer.EvaluateHallCreate(ctx, principal, reqCtx, input.OwnerUserID)
	if err != nil {
		return HallOutput{}, pctx, fmt.Errorf("failed to evaluate hall create: %w", err)
	}
	if !decision.Allow {
		return HallOutput{}, pctx, ErrForbidden
	}

	// 2. Create hall in repository
	hallID := uuid.New().String()
	hall := &domain.Hall{
		TenantID:      principal.TenantID,
		ID:            hallID,
		Name:          input.Name,
		OwnerUserID:   input.OwnerUserID,
		CurrentFilmID: input.CurrentFilmID,
	}

	stop := perf.Span(ctx, "db_ms")
	err = s.repo.Create(ctx, hall)
	stop()
	if err != nil {
		return HallOutput{}, pctx, fmt.Errorf("failed to create hall: %w", err)
	}

	// 3. Apply READ policy to response (read-shaped response pattern)
	result, err := s.enforcer.EnforceHallRead(ctx, principal, reqCtx, HallReadInput{
		HallID:        hallID,
		Name:          input.Name,
		OwnerUserID:   input.OwnerUserID,
		CurrentFilmID: input.CurrentFilmID,
	})
	if err != nil {
		return HallOutput{}, pctx, fmt.Errorf("failed to enforce hall read: %w", err)
	}

	// 4. Return response with read permissions applied
	return HallOutput{
		ID:             hallID,
		Name:           result.Name,
		OwnerUserID:    result.OwnerUserID,
		CurrentFilmID:  result.CurrentFilmID,
		SpectatorCount: 0, // New hall has no spectators
	}, pctx, nil
}
