package secured

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	securitymask "github.com/neoweyss/poc-dcs/backend-go/internal/security/mask"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type HallRepository struct {
	raw                  service.HallRepository
	classificationReader service.ClassificationMetadataReader
	logger               *slog.Logger
	bindingStore         service.BindingStore
	bindingVerifier      service.BindingVerifier
	bindingIssuer        service.BindingIssuer
	labelIssuer          service.LabelIssuer
}

func NewHallRepository(raw service.HallRepository, logger *slog.Logger, deps ...BindingDependencies) *HallRepository {
	var bindingDeps BindingDependencies
	if len(deps) > 0 {
		bindingDeps = deps[0]
	}
	return &HallRepository{
		raw:                  raw,
		classificationReader: bindingDeps.ClassificationReader,
		logger:               logger,
		bindingStore:         bindingDeps.Store,
		bindingVerifier:      bindingDeps.Verifier,
		bindingIssuer:        bindingDeps.Issuer,
		labelIssuer:          bindingDeps.LabelIssuer,
	}
}

func (r *HallRepository) ListCandidates(ctx context.Context, tenantID string) ([]service.HallReadCandidate, error) {
	_, err := r.accessContext(ctx)
	if err != nil {
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

	bindings, err := r.bindingStore.GetMany(ctx, tenantID, "hall", bindHallRecords(records))
	if err != nil {
		return nil, err
	}

	candidates := make([]service.HallReadCandidate, 0, len(records))
	for _, record := range records {
		if err := r.verifyBinding(ctx, record, bindings); err != nil {
			return nil, err
		}
		resource, err := service.BuildHallReadResource(ctx, r.classificationReader, record)
		if err != nil {
			return nil, err
		}

		spectatorCount, _ := r.raw.CountSpectators(ctx, tenantID, record.ID)
		candidates = append(candidates, service.HallReadCandidate{
			Record:         record,
			Resource:       resource,
			SpectatorCount: spectatorCount,
		})
	}

	return candidates, nil
}

func (r *HallRepository) Create(ctx context.Context, tenantID string, input service.HallCreateInput, decision service.Decision) (service.HallReadCandidate, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.HallReadCandidate{}, err
	}
	if !decision.Allow {
		return service.HallReadCandidate{}, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "hall"})
	}
	hall := &domain.Hall{
		TenantID:      tenantID,
		ID:            uuid.New().String(),
		Name:          input.Name,
		OwnerUserID:   input.OwnerUserID,
		CurrentFilmID: input.CurrentFilmID,
	}
	return r.persistCreate(ctx, access, hall)
}

func (r *HallRepository) persistCreate(ctx context.Context, access service.AccessContext, hall *domain.Hall) (service.HallReadCandidate, error) {
	if err := ensureBindingWriteDependencies(BindingDependencies{
		Store: r.bindingStore, Verifier: r.bindingVerifier, Issuer: r.bindingIssuer, LabelIssuer: r.labelIssuer,
	}); err != nil {
		return service.HallReadCandidate{}, err
	}

	if txRepo, ok := r.raw.(hallTxRepository); ok {
		if txStore, ok := r.bindingStore.(bindingTxStore); ok {
			if err := r.createInTx(ctx, txRepo, txStore, access, hall); err != nil {
				return service.HallReadCandidate{}, err
			}
			record := service.HallRecord{TenantID: hall.TenantID, ID: hall.ID, Name: hall.Name, OwnerUserID: hall.OwnerUserID, CurrentFilmID: hall.CurrentFilmID}
			resource, err := service.BuildHallReadResource(ctx, r.classificationReader, record)
			if err != nil {
				return service.HallReadCandidate{}, err
			}
			return service.HallReadCandidate{Record: record, Resource: resource, SpectatorCount: 0}, nil
		}
	}

	stop := perf.Span(ctx, "db_ms")
	err := r.raw.Create(ctx, hall)
	stop()
	if err != nil {
		return service.HallReadCandidate{}, err
	}

	if err := r.writeBinding(ctx, access, hall); err != nil {
		return service.HallReadCandidate{}, err
	}

	record := service.HallRecord{
		TenantID:      hall.TenantID,
		ID:            hall.ID,
		Name:          hall.Name,
		OwnerUserID:   hall.OwnerUserID,
		CurrentFilmID: hall.CurrentFilmID,
	}
	resource, err := service.BuildHallReadResource(ctx, r.classificationReader, record)
	if err != nil {
		return service.HallReadCandidate{}, err
	}
	return service.HallReadCandidate{Record: record, Resource: resource, SpectatorCount: 0}, nil
}

func (r *HallRepository) ApplyReadDecision(ctx context.Context, candidate service.HallReadCandidate, decision service.Decision) (service.HallReadView, error) {
	if !decision.Allow {
		return service.HallReadView{}, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "hall", "resource_id": candidate.Record.ID})
	}

	trackFields := decision.Reason != "dcs_off"
	fieldsMasked := []string{}
	fieldsDenied := []string{}

	var name *string
	switch r.hallAction(decision, "name") {
	case service.FieldActionDeny:
		if trackFields {
			fieldsDenied = append(fieldsDenied, "name")
		}
	case service.FieldActionMaskAfterDecrypt:
		masked := securitymask.String(candidate.Record.Name)
		name = &masked
		if trackFields {
			fieldsMasked = append(fieldsMasked, "name")
		}
	default:
		value := candidate.Record.Name
		name = &value
	}

	owner := r.shapeHallID(candidate.Record.OwnerUserID, r.hallAction(decision, "owner_user_id"), "owner_user_id", trackFields, &fieldsMasked, &fieldsDenied)
	currentFilm := r.shapeHallID(candidate.Record.CurrentFilmID, r.hallAction(decision, "current_film_id"), "current_film_id", trackFields, &fieldsMasked, &fieldsDenied)

	view := service.HallReadView{
		Output: service.HallOutput{
			ID:             candidate.Record.ID,
			Name:           name,
			OwnerUserID:    owner,
			CurrentFilmID:  currentFilm,
			SpectatorCount: candidate.SpectatorCount,
		},
		FieldsMasked:  fieldsMasked,
		FieldsDenied:  fieldsDenied,
		DecisionHash:  decision.Hash,
		PolicyID:      decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
	}
	if access, err := r.accessContext(ctx); err == nil {
		r.logTechnicalRead(withAction(access, service.ActionHallRead), candidate.Record, view)
	}
	return view, nil
}

func (r *HallRepository) hallAction(decision service.Decision, field string) service.FieldAction {
	if action, ok := decision.FieldActions[field]; ok && action != "" {
		return action
	}
	return service.FieldActionAllow
}

func (r *HallRepository) shapeHallID(value string, action service.FieldAction, field string, trackFields bool, masked *[]string, denied *[]string) interface{} {
	switch action {
	case service.FieldActionMaskAfterDecrypt:
		if trackFields {
			*masked = append(*masked, field)
		}
		return securitymask.UUID(value)
	case service.FieldActionDeny:
		if trackFields {
			*denied = append(*denied, field)
		}
		return nil
	default:
		return value
	}
}

func (r *HallRepository) accessContext(ctx context.Context) (service.AccessContext, error) {
	access, ok := service.AccessContextFromContext(ctx)
	if !ok {
		if r.logger != nil {
			r.logger.Warn("missing access context for hall repository")
		}
		return service.AccessContext{}, &service.ForbiddenError{Reason: "missing_access_context"}
	}
	return access, nil
}

func (r *HallRepository) verifyBinding(ctx context.Context, record service.HallRecord, bindings map[string]service.ResourceBinding) error {
	binding, ok := bindings[record.ID]
	if !ok {
		logBindingFailure(r.logger, "hall", record.ID, "binding_missing", map[string]interface{}{})
		return bindingFailureError("binding_missing", nil, map[string]interface{}{"resource_type": "hall", "resource_id": record.ID})
	}
	if err := r.bindingVerifier.Verify(ctx, buildHallPayload(record), binding.Label, binding.Binding); err != nil {
		reason := bindingReasonFromError(err)
		details := map[string]interface{}{"resource_type": "hall", "resource_id": record.ID}
		logBindingFailure(r.logger, "hall", record.ID, reason, details)
		return bindingFailureError(reason, &binding, details)
	}
	return nil
}

func (r *HallRepository) writeBinding(ctx context.Context, access service.AccessContext, hall *domain.Hall) error {
	label, err := r.labelIssuer.Issue(ctx, access, buildHallResource(hall))
	if err != nil {
		return err
	}
	bindingRecord, err := r.bindingIssuer.Create(ctx, buildHallPayload(service.HallRecord{
		TenantID:      hall.TenantID,
		ID:            hall.ID,
		Name:          hall.Name,
		OwnerUserID:   hall.OwnerUserID,
		CurrentFilmID: hall.CurrentFilmID,
	}), label)
	if err != nil {
		return err
	}
	return r.bindingStore.Upsert(ctx, service.ResourceBinding{
		TenantID:     hall.TenantID,
		ResourceType: "hall",
		ResourceID:   hall.ID,
		Label:        label,
		Binding:      bindingRecord,
	})
}

func (r *HallRepository) createInTx(ctx context.Context, txRepo hallTxRepository, txStore bindingTxStore, access service.AccessContext, hall *domain.Hall) error {
	tx, err := txRepo.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := txRepo.CreateInTx(ctx, tx, hall); err != nil {
		return err
	}

	label, err := r.labelIssuer.Issue(ctx, access, buildHallResource(hall))
	if err != nil {
		return err
	}
	bindingRecord, err := r.bindingIssuer.Create(ctx, buildHallPayload(service.HallRecord{
		TenantID:      hall.TenantID,
		ID:            hall.ID,
		Name:          hall.Name,
		OwnerUserID:   hall.OwnerUserID,
		CurrentFilmID: hall.CurrentFilmID,
	}), label)
	if err != nil {
		return err
	}
	if err := txStore.UpsertInTx(ctx, tx, service.ResourceBinding{
		TenantID:     hall.TenantID,
		ResourceType: "hall",
		ResourceID:   hall.ID,
		Label:        label,
		Binding:      bindingRecord,
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *HallRepository) logTechnicalRead(access service.AccessContext, record service.HallRecord, view service.HallReadView) {
	if r.logger == nil {
		return
	}

	r.logger.Debug("hall repository read enforced",
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
