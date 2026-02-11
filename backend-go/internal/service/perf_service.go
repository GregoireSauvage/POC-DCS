package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

type perfService struct {
	repo     repository.PerfLogRepository
	enforcer PolicyEnforcer
}

func NewPerfService(repo repository.PerfLogRepository, enforcer PolicyEnforcer) PerfService {
	return &perfService{
		repo:     repo,
		enforcer: enforcer,
	}
}

func (s *perfService) Write(ctx context.Context, log *domain.PerfLog) error {
	if s.repo == nil {
		return repository.ErrInvalidInput
	}
	return s.repo.Create(ctx, log)
}

func (s *perfService) List(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	limit int,
	action *string,
) ([]*domain.PerfLog, error) {
	// DCS enforcement (required - no fallback)
	// Perf endpoints expose sensitive performance data and MUST go through DCS PDP
	if s.enforcer == nil {
		return nil, ErrDCSNotConfigured
	}

	decision, err := s.enforcer.EvaluatePerfRead(ctx, principal, reqCtx)
	if err != nil {
		return nil, err
	}
	if !decision.Allow {
		return nil, ErrForbidden
	}

	if s.repo == nil {
		return nil, repository.ErrInvalidInput
	}
	if limit <= 0 {
		limit = 200
	}
	return s.repo.List(ctx, principal.TenantID, limit, action)
}

func (s *perfService) Summary(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	action *string,
	cacheLevel *int,
	allCacheLevels bool,
) ([]*domain.PerfSummary, error) {
	// DCS enforcement (required - no fallback)
	// Perf endpoints expose sensitive performance data and MUST go through DCS PDP
	if s.enforcer == nil {
		return nil, ErrDCSNotConfigured
	}

	decision, err := s.enforcer.EvaluatePerfRead(ctx, principal, reqCtx)
	if err != nil {
		return nil, err
	}
	if !decision.Allow {
		return nil, ErrForbidden
	}

	if s.repo == nil {
		return nil, repository.ErrInvalidInput
	}
	return s.repo.Summary(ctx, principal.TenantID, action, cacheLevel, allCacheLevels)
}
