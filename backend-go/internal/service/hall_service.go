package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

type hallService struct {
	repo       HallRepository
	secureRepo SecureHallRepository
	enforcer   PolicyEnforcer
	audit      *AuditService
	perf       PerfWriter
	runtime    RuntimeSettings
}

// NewHallService creates a new hall service
func NewHallService(repo HallRepository, enforcer PolicyEnforcer, audit *AuditService, perf PerfWriter, runtime RuntimeSettings) HallService {
	return &hallService{
		repo:     repo,
		enforcer: enforcer,
		audit:    audit,
		perf:     perf,
		runtime:  runtime,
	}
}

func NewHallServiceWithSecureRepo(
	repo HallRepository,
	secureRepo SecureHallRepository,
	enforcer PolicyEnforcer,
	audit *AuditService,
	perf PerfWriter,
	runtime RuntimeSettings,
) HallService {
	return &hallService{
		repo:       repo,
		secureRepo: secureRepo,
		enforcer:   enforcer,
		audit:      audit,
		perf:       perf,
		runtime:    runtime,
	}
}

// List returns all halls for the tenant with field-level enforcement
func (s *hallService) List(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) ([]HallOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionHallRead)

	if s.secureRepo != nil {
		views, err := s.secureRepo.ListByTenant(ctx, principal.TenantID)
		if err != nil {
			return nil, pctx, fmt.Errorf("failed to list halls: %w", err)
		}

		outputs := make([]HallOutput, 0, len(views))
		for _, view := range views {
			outputs = append(outputs, view.Output)
		}

		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.read", "hall")
		}

		return outputs, pctx, nil
	}

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

	// 4. Write perf log (after successful list)
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.read", "hall")
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
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionHallCreate)

	// 1. Authorization check
	decision, err := s.enforcer.EvaluateHallCreate(ctx, principal, reqCtx, input.OwnerUserID)
	if err != nil {
		return HallOutput{}, pctx, fmt.Errorf("failed to evaluate hall create: %w", err)
	}
	if !decision.Allow {
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
		}
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

	if s.secureRepo != nil {
		view, err := s.secureRepo.Create(ctx, hall)
		if err != nil {
			return HallOutput{}, pctx, fmt.Errorf("failed to create hall: %w", err)
		}

		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
		}

		return view.Output, pctx, nil
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
	output := HallOutput{
		ID:             hallID,
		Name:           result.Name,
		OwnerUserID:    result.OwnerUserID,
		CurrentFilmID:  result.CurrentFilmID,
		SpectatorCount: 0, // New hall has no spectators
	}

	// 5. Write perf log (after successful create)
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
	}

	return output, pctx, nil
}

func (s *hallService) writePerfLog(
	ctx context.Context,
	pctx *perf.Context,
	principal Principal,
	reqCtx RequestContext,
	action string,
	resourceType string,
) {
	if s.runtime == nil || s.perf == nil {
		return
	}
	metrics := pctx.Metrics()

	var pipMS, pdpMS, kmsMS, dbMS *float64
	if v, ok := metrics["pip_ms"]; ok {
		pipMS = &v
	}
	if v, ok := metrics["pdp_ms"]; ok {
		pdpMS = &v
	}
	if v, ok := metrics["kms_ms"]; ok {
		kmsMS = &v
	}
	if v, ok := metrics["db_ms"]; ok {
		dbMS = &v
	}

	_ = s.perf.Write(ctx, &domain.PerfLog{
		RequestID:     reqCtx.RequestID,
		TenantID:      principal.TenantID,
		SubjectUserID: principal.UserID,
		SubjectRole:   principal.Role,
		Action:        action,
		ResourceType:  resourceType,
		DCSEnabled:    s.runtime.DcsEnabled(),
		CacheLevel:    s.runtime.CacheLevel(),
		TotalMS:       pctx.TotalMS(),
		PIPMS:         pipMS,
		PDPMS:         pdpMS,
		KMSMS:         kmsMS,
		DBMS:          dbMS,
	})
}
