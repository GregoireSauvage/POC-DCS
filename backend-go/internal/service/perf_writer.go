package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// PerfWriter records perf logs produced by workflows.
type PerfWriter interface {
	Write(ctx context.Context, log *domain.PerfLog) error
}

// RuntimeSettings exposes runtime DCS settings for perf logging.
type RuntimeSettings interface {
	DcsEnabled() bool
	CacheLevel() int
}
