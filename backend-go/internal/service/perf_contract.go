package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// PerfService defines perf query operations for HTTP handlers.
type PerfService interface {
	List(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		limit int,
		action *string,
	) ([]*domain.PerfLog, error)

	Summary(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		action *string,
		cacheLevel *int,
		allCacheLevels bool,
	) ([]*domain.PerfSummary, error)
}
