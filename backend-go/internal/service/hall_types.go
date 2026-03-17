package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

// HallRecord is the raw database record
type HallRecord struct {
	TenantID      string
	ID            string
	Name          string
	OwnerUserID   string
	CurrentFilmID string
}

// HallOutput is the API response structure
type HallOutput struct {
	ID             interface{} `json:"id"`              // UUID or masked string
	Name           *string     `json:"name"`            // Can be null if denied
	OwnerUserID    interface{} `json:"owner_user_id"`   // UUID or masked string
	CurrentFilmID  interface{} `json:"current_film_id"` // UUID or masked string
	SpectatorCount int         `json:"spectator_count"` // Computed
}

// HallCreateInput is the input for creating a hall
type HallCreateInput struct {
	Name          string
	OwnerUserID   string
	CurrentFilmID string
}

// HallReadInput is the input for applying read policy
type HallReadInput struct {
	HallID        string
	Name          string
	OwnerUserID   string
	CurrentFilmID string
}

// HallReadResult is the result after applying field actions
type HallReadResult struct {
	Name          *string     // nil if denied
	OwnerUserID   interface{} // UUID or masked string
	CurrentFilmID interface{} // UUID or masked string
	FieldsMasked  []string
	FieldsDenied  []string
	DecisionHash  string
	PolicyID      string
	PolicyVersion string
}

type HallReadView struct {
	Output       HallOutput
	FieldsMasked []string
	FieldsDenied []string
	DecisionHash string
	PolicyID     string
	PolicyVersion string
}

type HallReadCandidate struct {
	Record         HallRecord
	Resource       Resource
	SpectatorCount int
}

// HallRepository defines hall data access operations
type HallRepository interface {
	ListByTenant(ctx context.Context, tenantID string) ([]HallRecord, error)
	Create(ctx context.Context, hall *domain.Hall) error
	CountSpectators(ctx context.Context, tenantID string, hallID string) (int, error)
	FindByID(ctx context.Context, tenantID string, hallID string) (*domain.Hall, error)
}

type SecureHallRepository interface {
	ListCandidates(ctx context.Context, tenantID string) ([]HallReadCandidate, error)
	Create(ctx context.Context, tenantID string, input HallCreateInput, decision Decision) (HallReadCandidate, error)
	ApplyReadDecision(ctx context.Context, candidate HallReadCandidate, decision Decision) (HallReadView, error)
}

// HallService defines hall business operations
type HallService interface {
	List(ctx context.Context, principal Principal, reqCtx RequestContext) ([]HallOutput, *perf.Context, error)
	Create(ctx context.Context, principal Principal, reqCtx RequestContext, input HallCreateInput) (HallOutput, *perf.Context, error)
}
