package secured

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/google/uuid"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	securitymask "github.com/neoweyss/poc-dcs/backend-go/internal/security/mask"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type SpectatorRepository struct {
	raw                  service.SpectatorRepository
	crypto               service.CryptoProvider
	runtime              service.RuntimeSettings
	classificationReader service.ClassificationMetadataReader
	logger               *slog.Logger
	bindingStore         service.BindingStore
	bindingVerifier      service.BindingVerifier
	bindingIssuer        service.BindingIssuer
	labelIssuer          service.LabelIssuer
}

func NewSpectatorRepository(
	raw service.SpectatorRepository,
	runtime service.RuntimeSettings,
	logger *slog.Logger,
	deps ...BindingDependencies,
) *SpectatorRepository {
	var bindingDeps BindingDependencies
	if len(deps) > 0 {
		bindingDeps = deps[0]
	}
	if runtime == nil {
		runtime = bindingDeps.Runtime
	}
	return &SpectatorRepository{
		raw:                  raw,
		crypto:               bindingDeps.Crypto,
		runtime:              runtime,
		classificationReader: bindingDeps.ClassificationReader,
		logger:               logger,
		bindingStore:         bindingDeps.Store,
		bindingVerifier:      bindingDeps.Verifier,
		bindingIssuer:        bindingDeps.Issuer,
		labelIssuer:          bindingDeps.LabelIssuer,
	}
}

func (r *SpectatorRepository) Create(ctx context.Context, tenantID string, input service.SpectatorCreateInput, decision service.Decision) (service.SpectatorReadCandidate, error) {
	access, err := r.accessContext(ctx)
	if err != nil {
		return service.SpectatorReadCandidate{}, err
	}
	if !decision.Allow {
		return service.SpectatorReadCandidate{}, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "spectator"})
	}

	if r.crypto == nil {
		return service.SpectatorReadCandidate{}, bindingFailureError("crypto_not_configured", nil, map[string]interface{}{"resource_type": "spectator"})
	}

	spectator := &domain.Spectator{TenantID: tenantID, ID: uuid.New().String(), HallID: input.HallID}

	stop := perf.Span(ctx, "kms_ms")
	nameCT, err := r.crypto.Encrypt(ctx, input.Name)
	if err != nil {
		stop()
		return service.SpectatorReadCandidate{}, err
	}
	ageCT, err := r.crypto.Encrypt(ctx, strconv.Itoa(input.Age))
	if err != nil {
		stop()
		return service.SpectatorReadCandidate{}, err
	}
	externalIDCT, err := r.crypto.Encrypt(ctx, input.ExternalID)
	if err != nil {
		stop()
		return service.SpectatorReadCandidate{}, err
	}
	pepper, err := r.crypto.GetPepper(ctx, service.DefaultSpectatorPepperPath)
	stop()
	if err != nil {
		return service.SpectatorReadCandidate{}, err
	}
	spectator.NameCT = nameCT
	spectator.AgeCT = ageCT
	spectator.ExternalIDCT = externalIDCT
	spectator.ExternalIDLookup = service.ComputeHMACLookup(pepper, service.NormalizeExternalID(input.ExternalID))
	return r.persistCreate(ctx, access, spectator)
}

func (r *SpectatorRepository) persistCreate(ctx context.Context, access service.AccessContext, spectator *domain.Spectator) (service.SpectatorReadCandidate, error) {
	if err := ensureBindingWriteDependencies(BindingDependencies{
		Store: r.bindingStore, Verifier: r.bindingVerifier, Issuer: r.bindingIssuer, LabelIssuer: r.labelIssuer,
	}); err != nil {
		return service.SpectatorReadCandidate{}, err
	}

	if txRepo, ok := r.raw.(spectatorTxRepository); ok {
		if txStore, ok := r.bindingStore.(bindingTxStore); ok {
			if err := r.createInTx(ctx, txRepo, txStore, access, spectator); err != nil {
				return service.SpectatorReadCandidate{}, err
			}
			resource, err := service.BuildSpectatorReadResource(ctx, r.classificationReader, spectator)
			if err != nil {
				return service.SpectatorReadCandidate{}, err
			}
			return service.SpectatorReadCandidate{Record: spectator, Resource: resource}, nil
		}
	}

	stop := perf.Span(ctx, "db_ms")
	err := r.raw.Create(ctx, spectator)
	stop()
	if err != nil {
		return service.SpectatorReadCandidate{}, err
	}

	if err := r.writeBinding(ctx, access, spectator); err != nil {
		return service.SpectatorReadCandidate{}, err
	}

	resource, err := service.BuildSpectatorReadResource(ctx, r.classificationReader, spectator)
	if err != nil {
		return service.SpectatorReadCandidate{}, err
	}
	return service.SpectatorReadCandidate{Record: spectator, Resource: resource}, nil
}

func (r *SpectatorRepository) SearchCandidatesByExternalID(ctx context.Context, tenantID string, externalID string, decision service.Decision) ([]service.SpectatorReadCandidate, error) {
	_, err := r.accessContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := ensureBindingReadDependencies(BindingDependencies{Store: r.bindingStore, Verifier: r.bindingVerifier}); err != nil {
		return nil, err
	}
	if !decision.Allow {
		return nil, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "spectator"})
	}

	if r.crypto == nil {
		return nil, bindingFailureError("crypto_not_configured", nil, map[string]interface{}{"resource_type": "spectator"})
	}

	pepper, err := r.crypto.GetPepper(ctx, service.DefaultSpectatorPepperPath)
	if err != nil {
		return nil, err
	}
	lookup := service.ComputeHMACLookup(pepper, service.NormalizeExternalID(externalID))

	stop := perf.Span(ctx, "db_ms")
	spectators, err := r.raw.FindByExternalIDLookup(ctx, tenantID, lookup)
	stop()
	if err != nil {
		return nil, err
	}

	bindings, err := r.bindingStore.GetMany(ctx, tenantID, "spectator", bindSpectatorRecords(spectators))
	if err != nil {
		return nil, err
	}

	candidates := make([]service.SpectatorReadCandidate, 0, len(spectators))
	for _, spectator := range spectators {
		if err := r.verifyBinding(ctx, spectator, bindings); err != nil {
			return nil, err
		}
		resource, err := service.BuildSpectatorReadResource(ctx, r.classificationReader, spectator)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, service.SpectatorReadCandidate{Record: spectator, Resource: resource})
	}

	return candidates, nil
}

func (r *SpectatorRepository) ApplyReadDecision(ctx context.Context, candidate service.SpectatorReadCandidate, decision service.Decision) (service.SpectatorReadView, error) {
	if !decision.Allow {
		return service.SpectatorReadView{}, forbiddenFromDecision(decision, map[string]interface{}{"resource_type": "spectator", "resource_id": candidate.Record.ID})
	}
	if r.crypto == nil {
		return service.SpectatorReadView{}, bindingFailureError("crypto_not_configured", nil, map[string]interface{}{"resource_type": "spectator", "resource_id": candidate.Record.ID})
	}

	trackFields := decision.Reason != "dcs_off"
	fieldsDecrypted := []string{}
	fieldsMasked := []string{}
	fieldsDenied := []string{}

	name, err := r.shapeEncryptedString(ctx, candidate.Record.NameCT, r.spectatorAction(decision, "name", true), "name", trackFields, &fieldsDecrypted, &fieldsMasked, &fieldsDenied)
	if err != nil {
		return service.SpectatorReadView{}, err
	}
	age, err := r.shapeEncryptedAge(ctx, candidate.Record.AgeCT, r.spectatorAction(decision, "age", true), trackFields, &fieldsDecrypted, &fieldsMasked, &fieldsDenied)
	if err != nil {
		return service.SpectatorReadView{}, err
	}
	externalID, err := r.shapeEncryptedString(ctx, candidate.Record.ExternalIDCT, r.spectatorAction(decision, "external_id", true), "external_id", trackFields, &fieldsDecrypted, &fieldsMasked, &fieldsDenied)
	if err != nil {
		return service.SpectatorReadView{}, err
	}

	access, err := r.accessContext(ctx)
	if err != nil {
		return service.SpectatorReadView{}, err
	}
	readAccess := withAction(access, service.ActionSpectatorRead)

	view := service.SpectatorReadView{
		Output: service.SpectatorOutput{
			ID:         r.maskedSpectatorID(readAccess, candidate.Record.ID),
			HallID:     candidate.Record.HallID,
			Name:       name,
			Age:        age,
			ExternalID: externalID,
		},
		FieldsDecrypted: fieldsDecrypted,
		FieldsMasked:    fieldsMasked,
		FieldsDenied:    fieldsDenied,
		DecisionHash:    decision.Hash,
		PolicyID:        decision.PolicyID,
		PolicyVersion:   decision.PolicyVersion,
	}
	r.logTechnicalRead(readAccess, candidate.Record, view)
	return view, nil
}

func (r *SpectatorRepository) spectatorAction(decision service.Decision, field string, encrypted bool) service.FieldAction {
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

func (r *SpectatorRepository) shapeEncryptedString(ctx context.Context, ciphertext string, action service.FieldAction, field string, trackFields bool, decrypted *[]string, masked *[]string, denied *[]string) (interface{}, error) {
	switch action {
	case service.FieldActionDeny:
		if trackFields {
			*denied = append(*denied, field)
		}
		return nil, nil
	default:
		plaintext, err := r.crypto.Decrypt(ctx, ciphertext)
		if err != nil {
			return nil, err
		}
		if action == service.FieldActionMaskAfterDecrypt {
			if trackFields {
				*masked = append(*masked, field)
			}
			return securitymask.Field(field, plaintext), nil
		}
		if trackFields && action == service.FieldActionDecrypt {
			*decrypted = append(*decrypted, field)
		}
		return plaintext, nil
	}
}

func (r *SpectatorRepository) shapeEncryptedAge(ctx context.Context, ciphertext string, action service.FieldAction, trackFields bool, decrypted *[]string, masked *[]string, denied *[]string) (interface{}, error) {
	switch action {
	case service.FieldActionDeny:
		if trackFields {
			*denied = append(*denied, "age")
		}
		return nil, nil
	default:
		plaintext, err := r.crypto.Decrypt(ctx, ciphertext)
		if err != nil {
			return nil, err
		}
		if action == service.FieldActionMaskAfterDecrypt {
			if trackFields {
				*masked = append(*masked, "age")
			}
			return securitymask.Field("age", plaintext), nil
		}
		if trackFields && action == service.FieldActionDecrypt {
			*decrypted = append(*decrypted, "age")
		}
		if parsed, err := strconv.Atoi(plaintext); err == nil {
			return parsed, nil
		}
		return plaintext, nil
	}
}

func (r *SpectatorRepository) maskedSpectatorID(access service.AccessContext, spectatorID string) interface{} {
	if r.runtime != nil && r.runtime.DcsEnabled() && access.Principal.Role != "admin" {
		return securitymask.UUID(spectatorID)
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

func (r *SpectatorRepository) verifyBinding(ctx context.Context, spectator *domain.Spectator, bindings map[string]service.ResourceBinding) error {
	binding, ok := bindings[spectator.ID]
	if !ok {
		logBindingFailure(r.logger, "spectator", spectator.ID, "binding_missing", map[string]interface{}{})
		return bindingFailureError("binding_missing", nil, map[string]interface{}{"resource_type": "spectator", "resource_id": spectator.ID})
	}
	if err := r.bindingVerifier.Verify(ctx, buildSpectatorPayload(spectator), binding.Label, binding.Binding); err != nil {
		reason := bindingReasonFromError(err)
		details := map[string]interface{}{"resource_type": "spectator", "resource_id": spectator.ID}
		logBindingFailure(r.logger, "spectator", spectator.ID, reason, details)
		return bindingFailureError(reason, &binding, details)
	}
	return nil
}

func (r *SpectatorRepository) writeBinding(ctx context.Context, access service.AccessContext, spectator *domain.Spectator) error {
	label, err := r.labelIssuer.Issue(ctx, access, buildSpectatorResource(spectator))
	if err != nil {
		return err
	}
	bindingRecord, err := r.bindingIssuer.Create(ctx, buildSpectatorPayload(spectator), label)
	if err != nil {
		return err
	}
	return r.bindingStore.Upsert(ctx, service.ResourceBinding{
		TenantID:     spectator.TenantID,
		ResourceType: "spectator",
		ResourceID:   spectator.ID,
		Label:        label,
		Binding:      bindingRecord,
	})
}

func (r *SpectatorRepository) createInTx(ctx context.Context, txRepo spectatorTxRepository, txStore bindingTxStore, access service.AccessContext, spectator *domain.Spectator) error {
	tx, err := txRepo.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := txRepo.CreateInTx(ctx, tx, spectator); err != nil {
		return err
	}
	label, err := r.labelIssuer.Issue(ctx, access, buildSpectatorResource(spectator))
	if err != nil {
		return err
	}
	bindingRecord, err := r.bindingIssuer.Create(ctx, buildSpectatorPayload(spectator), label)
	if err != nil {
		return err
	}
	if err := txStore.UpsertInTx(ctx, tx, service.ResourceBinding{
		TenantID:     spectator.TenantID,
		ResourceType: "spectator",
		ResourceID:   spectator.ID,
		Label:        label,
		Binding:      bindingRecord,
	}); err != nil {
		return err
	}

	return tx.Commit(ctx)
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
