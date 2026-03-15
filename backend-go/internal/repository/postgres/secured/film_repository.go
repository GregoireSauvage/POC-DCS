package secured

import (
	"context"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type FilmRepository struct {
	raw      service.FilmRepository
	enforcer service.PolicyEnforcer
	logger   *slog.Logger
}

func NewFilmRepository(raw service.FilmRepository, enforcer service.PolicyEnforcer, logger *slog.Logger) *FilmRepository {
	return &FilmRepository{
		raw:      raw,
		enforcer: enforcer,
		logger:   logger,
	}
}

func (r *FilmRepository) ListByTenant(ctx context.Context, tenantID string) ([]service.FilmReadView, error) {
	if _, err := r.accessContext(ctx); err != nil {
		return nil, err
	}

	stop := perf.Span(ctx, "db_ms")
	records, err := r.raw.ListByTenant(ctx, tenantID)
	stop()
	if err != nil {
		return nil, err
	}

	views := make([]service.FilmReadView, 0, len(records))
	for _, record := range records {
		view, err := r.secureRecord(ctx, record)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}

	return views, nil
}

func (r *FilmRepository) Create(ctx context.Context, tenantID, title, timeElapsedCT string) (service.FilmReadView, error) {
	if _, err := r.accessContext(ctx); err != nil {
		return service.FilmReadView{}, err
	}

	stop := perf.Span(ctx, "db_ms")
	record, err := r.raw.Create(ctx, tenantID, title, timeElapsedCT)
	stop()
	if err != nil {
		return service.FilmReadView{}, err
	}

	return r.secureRecord(ctx, record)
}

func (r *FilmRepository) UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (service.FilmReadView, error) {
	if _, err := r.accessContext(ctx); err != nil {
		return service.FilmReadView{}, err
	}

	stop := perf.Span(ctx, "db_ms")
	record, err := r.raw.UpdateTimeCiphertext(ctx, tenantID, filmID, ciphertext)
	stop()
	if err != nil {
		return service.FilmReadView{}, err
	}

	return r.secureRecord(ctx, record)
}

func (r *FilmRepository) secureRecord(ctx context.Context, record service.FilmRecord) (service.FilmReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.FilmReadView{}, err
	}

	result, err := r.enforcer.EnforceFilmRead(ctx, access.Principal, access.Request, service.FilmReadInput{
		FilmID:        record.ID,
		Title:         record.Title,
		TimeElapsedCT: record.TimeElapsedCT,
	})
	if err != nil {
		return service.FilmReadView{}, err
	}

	view := service.FilmReadView{
		Output: service.FilmOutput{
			ID:          record.ID,
			Title:       record.Title,
			TimeElapsed: result.TimeElapsed,
		},
		FieldsDecrypted: result.FieldsDecrypted,
		FieldsMasked:    result.FieldsMasked,
		FieldsDenied:    result.FieldsDenied,
	}

	r.logTechnicalRead(access, record, view)

	return view, nil
}

func (r *FilmRepository) accessContext(ctx context.Context) (service.AccessContext, error) {
	access, ok := service.AccessContextFromContext(ctx)
	if !ok {
		if r.logger != nil {
			r.logger.Warn("missing access context for secured film repository")
		}
		return service.AccessContext{}, &service.ForbiddenError{Reason: "missing_access_context"}
	}
	return access, nil
}

func (r *FilmRepository) logTechnicalRead(access service.AccessContext, record service.FilmRecord, view service.FilmReadView) {
	if r.logger == nil {
		return
	}

	r.logger.Debug("secured film repository read enforced",
		slog.String("request_id", access.Request.RequestID),
		slog.String("tenant_id", access.Principal.TenantID),
		slog.String("user_id", access.Principal.UserID),
		slog.String("role", access.Principal.Role),
		slog.String("action", string(access.Action)),
		slog.String("policy_action", string(service.ActionFilmRead)),
		slog.String("film_id", record.ID),
		slog.String("enforcement_layer", "repository"),
		slog.Int("fields_decrypted_count", len(view.FieldsDecrypted)),
		slog.Int("fields_masked_count", len(view.FieldsMasked)),
		slog.Int("fields_denied_count", len(view.FieldsDenied)),
	)
}
