package secured

import (
	"context"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type HallRepository struct {
	raw      service.HallRepository
	enforcer service.PolicyEnforcer
	logger   *slog.Logger
}

func NewHallRepository(raw service.HallRepository, enforcer service.PolicyEnforcer, logger *slog.Logger) *HallRepository {
	return &HallRepository{
		raw:      raw,
		enforcer: enforcer,
		logger:   logger,
	}
}

func (r *HallRepository) ListByTenant(ctx context.Context, tenantID string) ([]service.HallReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return nil, err
	}

	stop := perf.Span(ctx, "db_ms")
	records, err := r.raw.ListByTenant(ctx, tenantID)
	stop()
	if err != nil {
		return nil, err
	}

	views := make([]service.HallReadView, 0, len(records))
	for _, record := range records {
		view, err := r.secureRecord(ctx, access, record)
		if err != nil {
			return nil, err
		}

		spectatorCount, _ := r.raw.CountSpectators(ctx, tenantID, record.ID)
		view.Output.SpectatorCount = spectatorCount
		views = append(views, view)
	}

	return views, nil
}

func (r *HallRepository) Create(ctx context.Context, hall *domain.Hall) (service.HallReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.HallReadView{}, err
	}

	stop := perf.Span(ctx, "db_ms")
	err = r.raw.Create(ctx, hall)
	stop()
	if err != nil {
		return service.HallReadView{}, err
	}

	view, err := r.secureRecord(ctx, access, service.HallRecord{
		TenantID:      hall.TenantID,
		ID:            hall.ID,
		Name:          hall.Name,
		OwnerUserID:   hall.OwnerUserID,
		CurrentFilmID: hall.CurrentFilmID,
	})
	if err != nil {
		return service.HallReadView{}, err
	}
	view.Output.SpectatorCount = 0

	return view, nil
}

func (r *HallRepository) secureRecord(ctx context.Context, access service.AccessContext, record service.HallRecord) (service.HallReadView, error) {
	result, err := r.enforcer.EnforceHallRead(ctx, access.Principal, access.Request, service.HallReadInput{
		HallID:        record.ID,
		Name:          record.Name,
		OwnerUserID:   record.OwnerUserID,
		CurrentFilmID: record.CurrentFilmID,
	})
	if err != nil {
		return service.HallReadView{}, err
	}

	view := service.HallReadView{
		Output: service.HallOutput{
			ID:            record.ID,
			Name:          result.Name,
			OwnerUserID:   result.OwnerUserID,
			CurrentFilmID: result.CurrentFilmID,
		},
		FieldsMasked:  result.FieldsMasked,
		FieldsDenied:  result.FieldsDenied,
		DecisionHash:  result.DecisionHash,
		PolicyID:      result.PolicyID,
		PolicyVersion: result.PolicyVersion,
	}

	r.logTechnicalRead(access, record, view)

	return view, nil
}

func (r *HallRepository) accessContext(ctx context.Context) (service.AccessContext, error) {
	access, ok := service.AccessContextFromContext(ctx)
	if !ok {
		if r.logger != nil {
			r.logger.Warn("missing access context for secured hall repository")
		}
		return service.AccessContext{}, &service.ForbiddenError{Reason: "missing_access_context"}
	}
	return access, nil
}

func (r *HallRepository) logTechnicalRead(access service.AccessContext, record service.HallRecord, view service.HallReadView) {
	if r.logger == nil {
		return
	}

	r.logger.Debug("secured hall repository read enforced",
		slog.String("request_id", access.Request.RequestID),
		slog.String("tenant_id", access.Principal.TenantID),
		slog.String("user_id", access.Principal.UserID),
		slog.String("role", access.Principal.Role),
		slog.String("action", string(access.Action)),
		slog.String("policy_action", string(service.ActionHallRead)),
		slog.String("hall_id", record.ID),
		slog.String("enforcement_layer", "repository"),
		slog.Int("fields_masked_count", len(view.FieldsMasked)),
		slog.Int("fields_denied_count", len(view.FieldsDenied)),
	)
}
