package secured

import (
	"context"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type FilmRepository struct {
	raw             service.FilmRepository
	enforcer        service.PolicyEnforcer
	logger          *slog.Logger
	bindingStore    service.BindingStore
	bindingVerifier service.BindingVerifier
	bindingIssuer   service.BindingIssuer
	labelIssuer     service.LabelIssuer
}

func NewFilmRepository(raw service.FilmRepository, enforcer service.PolicyEnforcer, logger *slog.Logger, deps ...BindingDependencies) *FilmRepository {
	var bindingDeps BindingDependencies
	if len(deps) > 0 {
		bindingDeps = deps[0]
	}
	return &FilmRepository{
		raw:             raw,
		enforcer:        enforcer,
		logger:          logger,
		bindingStore:    bindingDeps.Store,
		bindingVerifier: bindingDeps.Verifier,
		bindingIssuer:   bindingDeps.Issuer,
		labelIssuer:     bindingDeps.LabelIssuer,
	}
}

func (r *FilmRepository) ListByTenant(ctx context.Context, tenantID string) ([]service.FilmReadView, error) {
	if _, err := r.accessContext(ctx); err != nil {
		return nil, err
	}
	if err := ensureBindingReadDependencies(BindingDependencies{Store: r.bindingStore, Verifier: r.bindingVerifier}); err != nil {
		return nil, err
	}

	stop := perf.Span(ctx, "db_ms")
	records, err := r.raw.ListByTenant(ctx, tenantID)
	stop()
	if err != nil {
		return nil, err
	}

	bindings, err := r.bindingStore.GetMany(ctx, tenantID, "film", bindFilmRecords(records))
	if err != nil {
		return nil, err
	}

	views := make([]service.FilmReadView, 0, len(records))
	for _, record := range records {
		if err := r.verifyBinding(ctx, record, bindings); err != nil {
			return nil, err
		}
		view, err := r.secureRecord(ctx, record)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}

	return views, nil
}

func (r *FilmRepository) Create(ctx context.Context, tenantID, title, timeElapsedCT string) (service.FilmReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.FilmReadView{}, err
	}
	if err := ensureBindingWriteDependencies(BindingDependencies{
		Store: r.bindingStore, Verifier: r.bindingVerifier, Issuer: r.bindingIssuer, LabelIssuer: r.labelIssuer,
	}); err != nil {
		return service.FilmReadView{}, err
	}

	if txRepo, ok := r.raw.(filmTxRepository); ok {
		if txStore, ok := r.bindingStore.(bindingTxStore); ok {
			record, err := r.createInTx(ctx, txRepo, txStore, access, tenantID, title, timeElapsedCT)
			if err != nil {
				return service.FilmReadView{}, err
			}
			return r.secureRecord(ctx, record)
		}
	}

	stop := perf.Span(ctx, "db_ms")
	record, err := r.raw.Create(ctx, tenantID, title, timeElapsedCT)
	stop()
	if err != nil {
		return service.FilmReadView{}, err
	}

	if err := r.writeBinding(ctx, access, record); err != nil {
		return service.FilmReadView{}, err
	}

	return r.secureRecord(ctx, record)
}

func (r *FilmRepository) UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (service.FilmReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.FilmReadView{}, err
	}
	if err := ensureBindingWriteDependencies(BindingDependencies{
		Store: r.bindingStore, Verifier: r.bindingVerifier, Issuer: r.bindingIssuer, LabelIssuer: r.labelIssuer,
	}); err != nil {
		return service.FilmReadView{}, err
	}

	if txRepo, ok := r.raw.(filmTxRepository); ok {
		if txStore, ok := r.bindingStore.(bindingTxStore); ok {
			record, err := r.updateInTx(ctx, txRepo, txStore, access, tenantID, filmID, ciphertext)
			if err != nil {
				return service.FilmReadView{}, err
			}
			return r.secureRecord(ctx, record)
		}
	}

	stop := perf.Span(ctx, "db_ms")
	record, err := r.raw.UpdateTimeCiphertext(ctx, tenantID, filmID, ciphertext)
	stop()
	if err != nil {
		return service.FilmReadView{}, err
	}

	if err := r.writeBinding(ctx, access, record); err != nil {
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
		DecisionHash:    result.DecisionHash,
		PolicyID:        result.PolicyID,
		PolicyVersion:   result.PolicyVersion,
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

func (r *FilmRepository) verifyBinding(ctx context.Context, record service.FilmRecord, bindings map[string]service.ResourceBinding) error {
	binding, ok := bindings[record.ID]
	if !ok {
		logBindingFailure(r.logger, "film", record.ID, "binding_missing", map[string]interface{}{})
		return bindingFailureError("binding_missing", nil, map[string]interface{}{"resource_type": "film", "resource_id": record.ID})
	}
	if err := r.bindingVerifier.Verify(ctx, buildFilmPayload(record), binding.Label, binding.Binding); err != nil {
		reason := bindingReasonFromError(err)
		details := map[string]interface{}{"resource_type": "film", "resource_id": record.ID}
		logBindingFailure(r.logger, "film", record.ID, reason, details)
		return bindingFailureError(reason, &binding, details)
	}
	return nil
}

func (r *FilmRepository) writeBinding(ctx context.Context, access service.AccessContext, record service.FilmRecord) error {
	resource := buildFilmResource(record)
	label, err := r.labelIssuer.Issue(ctx, access, resource)
	if err != nil {
		return err
	}
	bindingRecord, err := r.bindingIssuer.Create(ctx, buildFilmPayload(record), label)
	if err != nil {
		return err
	}
	return r.bindingStore.Upsert(ctx, service.ResourceBinding{
		TenantID:     record.TenantID,
		ResourceType: "film",
		ResourceID:   record.ID,
		Label:        label,
		Binding:      bindingRecord,
	})
}

func (r *FilmRepository) createInTx(
	ctx context.Context,
	txRepo filmTxRepository,
	txStore bindingTxStore,
	access service.AccessContext,
	tenantID, title, timeElapsedCT string,
) (service.FilmRecord, error) {
	tx, err := txRepo.BeginTx(ctx)
	if err != nil {
		return service.FilmRecord{}, err
	}
	defer tx.Rollback(ctx)

	record, err := txRepo.CreateInTx(ctx, tx, tenantID, title, timeElapsedCT)
	if err != nil {
		return service.FilmRecord{}, err
	}

	label, err := r.labelIssuer.Issue(ctx, access, buildFilmResource(record))
	if err != nil {
		return service.FilmRecord{}, err
	}
	bindingRecord, err := r.bindingIssuer.Create(ctx, buildFilmPayload(record), label)
	if err != nil {
		return service.FilmRecord{}, err
	}
	if err := txStore.UpsertInTx(ctx, tx, service.ResourceBinding{
		TenantID:     record.TenantID,
		ResourceType: "film",
		ResourceID:   record.ID,
		Label:        label,
		Binding:      bindingRecord,
	}); err != nil {
		return service.FilmRecord{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return service.FilmRecord{}, err
	}
	return record, nil
}

func (r *FilmRepository) updateInTx(
	ctx context.Context,
	txRepo filmTxRepository,
	txStore bindingTxStore,
	access service.AccessContext,
	tenantID, filmID, ciphertext string,
) (service.FilmRecord, error) {
	tx, err := txRepo.BeginTx(ctx)
	if err != nil {
		return service.FilmRecord{}, err
	}
	defer tx.Rollback(ctx)

	record, err := txRepo.UpdateTimeCiphertextInTx(ctx, tx, tenantID, filmID, ciphertext)
	if err != nil {
		return service.FilmRecord{}, err
	}

	label, err := r.labelIssuer.Issue(ctx, access, buildFilmResource(record))
	if err != nil {
		return service.FilmRecord{}, err
	}
	bindingRecord, err := r.bindingIssuer.Create(ctx, buildFilmPayload(record), label)
	if err != nil {
		return service.FilmRecord{}, err
	}
	if err := txStore.UpsertInTx(ctx, tx, service.ResourceBinding{
		TenantID:     record.TenantID,
		ResourceType: "film",
		ResourceID:   record.ID,
		Label:        label,
		Binding:      bindingRecord,
	}); err != nil {
		return service.FilmRecord{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return service.FilmRecord{}, err
	}
	return record, nil
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
