package secured

import (
	"context"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type SpectatorRepository struct {
	raw      service.SpectatorRepository
	enforcer service.PolicyEnforcer
	runtime  service.RuntimeSettings
	logger   *slog.Logger
}

func NewSpectatorRepository(
	raw service.SpectatorRepository,
	enforcer service.PolicyEnforcer,
	runtime service.RuntimeSettings,
	logger *slog.Logger,
) *SpectatorRepository {
	return &SpectatorRepository{
		raw:      raw,
		enforcer: enforcer,
		runtime:  runtime,
		logger:   logger,
	}
}

func (r *SpectatorRepository) Create(ctx context.Context, spectator *domain.Spectator) (service.SpectatorReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.SpectatorReadView{}, err
	}

	stop := perf.Span(ctx, "db_ms")
	err = r.raw.Create(ctx, spectator)
	stop()
	if err != nil {
		return service.SpectatorReadView{}, err
	}

	return r.secureSpectator(ctx, access, spectator)
}

func (r *SpectatorRepository) SearchByExternalID(ctx context.Context, tenantID string, externalID string) ([]service.SpectatorReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return nil, err
	}

	decision, err := r.enforcer.EvaluateSpectatorSearch(ctx, access.Principal, access.Request)
	if err != nil {
		return nil, err
	}
	if !decision.Allow {
		return nil, &service.ForbiddenError{DecisionHash: decision.DecisionHash, Reason: decision.Reason}
	}

	pepper, err := r.enforcer.GetPepper(ctx, service.DefaultSpectatorPepperPath)
	if err != nil {
		return nil, err
	}
	lookup := kms.ComputeHMACLookup(pepper, kms.NormalizeExternalID(externalID))

	stop := perf.Span(ctx, "db_ms")
	spectators, err := r.raw.FindByExternalIDLookup(ctx, tenantID, lookup)
	stop()
	if err != nil {
		return nil, err
	}

	views := make([]service.SpectatorReadView, 0, len(spectators))
	for _, spectator := range spectators {
		view, err := r.secureSpectator(ctx, access, spectator)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}

	return views, nil
}

func (r *SpectatorRepository) secureSpectator(ctx context.Context, access service.AccessContext, spectator *domain.Spectator) (service.SpectatorReadView, error) {
	result, err := r.enforcer.EnforceSpectatorRead(ctx, access.Principal, access.Request, service.SpectatorReadInput{
		SpectatorID:  spectator.ID,
		HallID:       spectator.HallID,
		NameCT:       spectator.NameCT,
		AgeCT:        spectator.AgeCT,
		ExternalIDCT: spectator.ExternalIDCT,
	})
	if err != nil {
		return service.SpectatorReadView{}, err
	}

	view := service.SpectatorReadView{
		Output: service.SpectatorOutput{
			ID:         r.maskedSpectatorID(access, spectator.ID),
			HallID:     spectator.HallID,
			Name:       result.Name,
			Age:        result.Age,
			ExternalID: result.ExternalID,
		},
		FieldsDecrypted: result.FieldsDecrypted,
		FieldsMasked:    result.FieldsMasked,
		FieldsDenied:    result.FieldsDenied,
	}

	r.logTechnicalRead(access, spectator, view)

	return view, nil
}

func (r *SpectatorRepository) maskedSpectatorID(access service.AccessContext, spectatorID string) interface{} {
	if r.runtime != nil && r.runtime.DcsEnabled() && access.Principal.Role != "admin" {
		return pep.MaskUUID(spectatorID)
	}
	return spectatorID
}

func (r *SpectatorRepository) accessContext(ctx context.Context) (service.AccessContext, error) {
	access, ok := service.AccessContextFromContext(ctx)
	if !ok {
		if r.logger != nil {
			r.logger.Warn("missing access context for secured spectator repository")
		}
		return service.AccessContext{}, &service.ForbiddenError{Reason: "missing_access_context"}
	}
	return access, nil
}

func (r *SpectatorRepository) logTechnicalRead(access service.AccessContext, spectator *domain.Spectator, view service.SpectatorReadView) {
	if r.logger == nil {
		return
	}

	r.logger.Debug("secured spectator repository read enforced",
		slog.String("request_id", access.Request.RequestID),
		slog.String("tenant_id", access.Principal.TenantID),
		slog.String("user_id", access.Principal.UserID),
		slog.String("role", access.Principal.Role),
		slog.String("action", string(access.Action)),
		slog.String("policy_action", string(service.ActionSpectatorRead)),
		slog.String("spectator_id", spectator.ID),
		slog.String("hall_id", spectator.HallID),
		slog.String("enforcement_layer", "repository"),
		slog.Int("fields_decrypted_count", len(view.FieldsDecrypted)),
		slog.Int("fields_masked_count", len(view.FieldsMasked)),
		slog.Int("fields_denied_count", len(view.FieldsDenied)),
	)
}
