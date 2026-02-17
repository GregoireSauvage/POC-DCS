package repository

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// PerfLogRepository defines perf log persistence operations.
type PerfLogRepository interface {
	// Create inserts a new perf log entry.
	Create(ctx context.Context, log *domain.PerfLog) error

	// List returns perf logs for a tenant with optional action filter.
	List(ctx context.Context, tenantID string, limit int, action *string, source *string) ([]*domain.PerfLog, error)

	// Summary returns aggregated perf results for a tenant with filters.
	Summary(
		ctx context.Context,
		tenantID string,
		action *string,
		cacheLevel *int,
		allCacheLevels bool,
		source *string,
	) ([]*domain.PerfSummary, error)
}
