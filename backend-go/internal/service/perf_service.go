package service

import (
	"context"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

type perfService struct {
	repo       repository.PerfLogRepository
	authorizer Authorizer
	source     string
}

func NewPerfService(repo repository.PerfLogRepository, authorizer Authorizer, source string) PerfService {
	return &perfService{
		repo:       repo,
		authorizer: authorizer,
		source:     source,
	}
}

func (s *perfService) Write(ctx context.Context, log *domain.PerfLog) error {
	if s.repo == nil {
		return repository.ErrInvalidInput
	}
	if log.Source == "" {
		log.Source = normalizePerfSource(s.source)
	}
	return s.repo.Create(ctx, log)
}

func (s *perfService) List(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	limit int,
	action *string,
	source *string,
) ([]*domain.PerfLog, error) {
	if s.authorizer != nil {
		decision, err := s.authorizer.Authorize(ctx, PolicyInput{
			Access: AccessContext{Principal: principal, Request: reqCtx, Action: ActionPerfRead},
			Resource: Resource{
				Type:     "perf",
				TenantID: principal.TenantID,
				Fields:   map[string]FieldMeta{},
			},
		})
		if err != nil {
			return nil, err
		}
		if !decision.Allow {
			return nil, ErrForbidden
		}
	} else {
		return nil, ErrDCSNotConfigured
	}

	if s.repo == nil {
		return nil, repository.ErrInvalidInput
	}
	if limit <= 0 {
		limit = 200
	}
	effectiveSource := source
	if effectiveSource == nil || strings.TrimSpace(*effectiveSource) == "" {
		src := normalizePerfSource(s.source)
		effectiveSource = &src
	}
	return s.repo.List(ctx, principal.TenantID, limit, action, effectiveSource)
}

func (s *perfService) Summary(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	action *string,
	cacheLevel *int,
	allCacheLevels bool,
	source *string,
) ([]*domain.PerfSummary, error) {
	if s.authorizer != nil {
		decision, err := s.authorizer.Authorize(ctx, PolicyInput{
			Access: AccessContext{Principal: principal, Request: reqCtx, Action: ActionPerfRead},
			Resource: Resource{
				Type:     "perf",
				TenantID: principal.TenantID,
				Fields:   map[string]FieldMeta{},
			},
		})
		if err != nil {
			return nil, err
		}
		if !decision.Allow {
			return nil, ErrForbidden
		}
	} else {
		return nil, ErrDCSNotConfigured
	}

	if s.repo == nil {
		return nil, repository.ErrInvalidInput
	}
	effectiveSource := source
	if effectiveSource == nil || strings.TrimSpace(*effectiveSource) == "" {
		src := normalizePerfSource(s.source)
		effectiveSource = &src
	}
	return s.repo.Summary(ctx, principal.TenantID, action, cacheLevel, allCacheLevels, effectiveSource)
}

func normalizePerfSource(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return strings.TrimSpace(value)
}
