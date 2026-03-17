package secured

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	securitymask "github.com/neoweyss/poc-dcs/backend-go/internal/security/mask"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type FilmRepository struct {
	raw                  service.FilmRepository
	crypto               service.CryptoProvider
	classificationReader service.ClassificationMetadataReader
	logger               *slog.Logger
	bindingStore         service.BindingStore
	bindingVerifier      service.BindingVerifier
	bindingIssuer        service.BindingIssuer
	labelIssuer          service.LabelIssuer
}

func NewFilmRepository(raw service.FilmRepository, logger *slog.Logger, deps ...BindingDependencies) *FilmRepository {
	var bindingDeps BindingDependencies
	if len(deps) > 0 {
		bindingDeps = deps[0]
	}
	return &FilmRepository{
		raw:                  raw,
		crypto:               bindingDeps.Crypto,
		classificationReader: bindingDeps.ClassificationReader,
		logger:               logger,
		bindingStore:         bindingDeps.Store,
		bindingVerifier:      bindingDeps.Verifier,
		bindingIssuer:        bindingDeps.Issuer,
		labelIssuer:          bindingDeps.LabelIssuer,
	}
}

func (r *FilmRepository) ListCandidates(ctx context.Context, tenantID string) ([]service.FilmReadCandidate, error) {
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

	candidates := make([]service.FilmReadCandidate, 0, len(records))
	for _, record := range records {
		if err := r.verifyBinding(ctx, record, bindings); err != nil {
			return nil, err
		}
		candidate, err := r.candidateFromRecord(ctx, record)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}

	return candidates, nil
}

func (r *FilmRepository) Create(ctx context.Context, tenantID string, input service.FilmCreateInput, decision service.Decision) (service.FilmReadCandidate, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.FilmReadCandidate{}, err
	}
	if !decision.Allow {
		return service.FilmReadCandidate{}, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "film"})
	}
	if r.crypto == nil {
		return service.FilmReadCandidate{}, fmt.Errorf("film crypto not configured")
	}

	stop := perf.Span(ctx, "kms_ms")
	ciphertext, err := r.crypto.Encrypt(ctx, strconv.Itoa(input.TimeElapsed))
	stop()
	if err != nil {
		return service.FilmReadCandidate{}, err
	}

	record, err := r.persistCreate(ctx, access, tenantID, input.Title, ciphertext)
	if err != nil {
		return service.FilmReadCandidate{}, err
	}

	return r.candidateFromRecord(ctx, record)
}

func (r *FilmRepository) UpdateTime(ctx context.Context, tenantID, filmID string, timeElapsed int, decision service.Decision) (service.FilmReadCandidate, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.FilmReadCandidate{}, err
	}
	if !decision.Allow {
		return service.FilmReadCandidate{}, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "film", "resource_id": filmID})
	}
	if r.crypto == nil {
		return service.FilmReadCandidate{}, fmt.Errorf("film crypto not configured")
	}

	stop := perf.Span(ctx, "kms_ms")
	ciphertext, err := r.crypto.Encrypt(ctx, strconv.Itoa(timeElapsed))
	stop()
	if err != nil {
		return service.FilmReadCandidate{}, err
	}

	record, err := r.persistUpdate(ctx, access, tenantID, filmID, ciphertext)
	if err != nil {
		return service.FilmReadCandidate{}, err
	}

	return r.candidateFromRecord(ctx, record)
}

func (r *FilmRepository) ApplyReadDecision(ctx context.Context, candidate service.FilmReadCandidate, decision service.Decision) (service.FilmReadView, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.FilmReadView{}, err
	}
	if !decision.Allow {
		return service.FilmReadView{}, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "film", "resource_id": candidate.Record.ID})
	}

	view, err := r.shapeRead(ctx, candidate.Record, decision)
	if err != nil {
		return service.FilmReadView{}, err
	}
	view.DecisionHash = decision.Hash
	view.PolicyID = decision.PolicyID
	view.PolicyVersion = decision.PolicyVersion

	r.logTechnicalRead(access, candidate.Record, view)
	return view, nil
}

func (r *FilmRepository) persistCreate(ctx context.Context, access service.AccessContext, tenantID, title, timeElapsedCT string) (service.FilmRecord, error) {
	if err := ensureBindingWriteDependencies(BindingDependencies{
		Store: r.bindingStore, Verifier: r.bindingVerifier, Issuer: r.bindingIssuer, LabelIssuer: r.labelIssuer,
	}); err != nil {
		return service.FilmRecord{}, err
	}

	if txRepo, ok := r.raw.(filmTxRepository); ok {
		if txStore, ok := r.bindingStore.(bindingTxStore); ok {
			return r.createInTx(ctx, txRepo, txStore, access, tenantID, title, timeElapsedCT)
		}
	}

	stop := perf.Span(ctx, "db_ms")
	record, err := r.raw.Create(ctx, tenantID, title, timeElapsedCT)
	stop()
	if err != nil {
		return service.FilmRecord{}, err
	}

	if err := r.writeBinding(ctx, access, record); err != nil {
		return service.FilmRecord{}, err
	}

	return record, nil
}

func (r *FilmRepository) persistUpdate(ctx context.Context, access service.AccessContext, tenantID, filmID, ciphertext string) (service.FilmRecord, error) {
	if err := ensureBindingWriteDependencies(BindingDependencies{
		Store: r.bindingStore, Verifier: r.bindingVerifier, Issuer: r.bindingIssuer, LabelIssuer: r.labelIssuer,
	}); err != nil {
		return service.FilmRecord{}, err
	}

	if txRepo, ok := r.raw.(filmTxRepository); ok {
		if txStore, ok := r.bindingStore.(bindingTxStore); ok {
			return r.updateInTx(ctx, txRepo, txStore, access, tenantID, filmID, ciphertext)
		}
	}

	stop := perf.Span(ctx, "db_ms")
	record, err := r.raw.UpdateTimeCiphertext(ctx, tenantID, filmID, ciphertext)
	stop()
	if err != nil {
		return service.FilmRecord{}, err
	}

	if err := r.writeBinding(ctx, access, record); err != nil {
		return service.FilmRecord{}, err
	}

	return record, nil
}

func (r *FilmRepository) shapeRead(ctx context.Context, record service.FilmRecord, decision service.Decision) (service.FilmReadView, error) {
	if r.crypto == nil {
		return service.FilmReadView{}, fmt.Errorf("film crypto not configured")
	}

	trackFields := decision.Reason != "dcs_off"
	fieldsDecrypted := []string{}
	fieldsMasked := []string{}
	fieldsDenied := []string{}

	title := record.Title
	switch r.filmAction(decision, "title", false) {
	case service.FieldActionMaskAfterDecrypt:
		title = securitymask.String(record.Title)
		if trackFields {
			fieldsMasked = append(fieldsMasked, "title")
		}
	case service.FieldActionDeny:
		title = ""
		if trackFields {
			fieldsDenied = append(fieldsDenied, "title")
		}
	}

	timeElapsed := interface{}(nil)
	switch r.filmAction(decision, "time_elapsed", true) {
	case service.FieldActionDeny:
		if trackFields {
			fieldsDenied = append(fieldsDenied, "time_elapsed")
		}
	default:
		stop := perf.Span(ctx, "kms_ms")
		plaintext, err := r.crypto.Decrypt(ctx, record.TimeElapsedCT)
		stop()
		if err != nil {
			return service.FilmReadView{}, err
		}
		action := r.filmAction(decision, "time_elapsed", true)
		if action == service.FieldActionMaskAfterDecrypt {
			timeElapsed = securitymask.Field("time_elapsed", plaintext)
			if trackFields {
				fieldsMasked = append(fieldsMasked, "time_elapsed")
			}
		} else {
			if parsed, err := strconv.Atoi(plaintext); err == nil {
				timeElapsed = parsed
			} else {
				timeElapsed = plaintext
			}
			if trackFields && action == service.FieldActionDecrypt {
				fieldsDecrypted = append(fieldsDecrypted, "time_elapsed")
			}
		}
	}

	return service.FilmReadView{
		Output: service.FilmOutput{
			ID:          record.ID,
			Title:       title,
			TimeElapsed: timeElapsed,
		},
		FieldsDecrypted: fieldsDecrypted,
		FieldsMasked:    fieldsMasked,
		FieldsDenied:    fieldsDenied,
	}, nil
}

func (r *FilmRepository) candidateFromRecord(ctx context.Context, record service.FilmRecord) (service.FilmReadCandidate, error) {
	resource, err := service.BuildFilmReadResource(ctx, r.classificationReader, record)
	if err != nil {
		return service.FilmReadCandidate{}, err
	}
	return service.FilmReadCandidate{Record: record, Resource: resource}, nil
}

func (r *FilmRepository) filmAction(decision service.Decision, field string, encrypted bool) service.FieldAction {
	if action, ok := decision.FieldActions[field]; ok && action != "" {
		return action
	}
	if decision.Reason == "dcs_off" {
		if encrypted {
			return service.FieldActionDecrypt
		}
		return service.FieldActionAllow
	}
	return service.FieldActionAllow
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
