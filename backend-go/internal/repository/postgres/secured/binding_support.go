package secured

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type BindingDependencies struct {
	Store                service.BindingStore
	Verifier             service.BindingVerifier
	Issuer               service.BindingIssuer
	LabelIssuer          service.LabelIssuer
	Authorizer           service.Authorizer
	Crypto               service.CryptoProvider
	ClassificationReader service.ClassificationMetadataReader
	Runtime              service.RuntimeSettings
}

type bindingTxStore interface {
	UpsertInTx(ctx context.Context, tx pgx.Tx, binding service.ResourceBinding) error
}

type filmTxRepository interface {
	service.FilmRepository
	BeginTx(ctx context.Context) (pgx.Tx, error)
	CreateInTx(ctx context.Context, tx interface {
		QueryRow(context.Context, string, ...interface{}) pgx.Row
	}, tenantID, title, timeElapsedCT string) (service.FilmRecord, error)
	UpdateTimeCiphertextInTx(ctx context.Context, tx interface {
		QueryRow(context.Context, string, ...interface{}) pgx.Row
	}, tenantID, filmID, ciphertext string) (service.FilmRecord, error)
}

type hallTxRepository interface {
	service.HallRepository
	BeginTx(ctx context.Context) (pgx.Tx, error)
	CreateInTx(ctx context.Context, tx interface {
		Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	}, hall *domain.Hall) error
}

type spectatorTxRepository interface {
	service.SpectatorRepository
	BeginTx(ctx context.Context) (pgx.Tx, error)
	CreateInTx(ctx context.Context, tx interface {
		Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	}, spectator *domain.Spectator) error
}

func ensureBindingReadDependencies(deps BindingDependencies) error {
	if deps.Store == nil || deps.Verifier == nil {
		return bindingFailureError("binding_not_configured", nil, nil)
	}
	return nil
}

func ensureBindingWriteDependencies(deps BindingDependencies) error {
	if err := ensureBindingReadDependencies(deps); err != nil {
		return err
	}
	if deps.Issuer == nil || deps.LabelIssuer == nil {
		return bindingFailureError("binding_not_configured", nil, nil)
	}
	return nil
}

func bindingFailureError(reason string, binding *service.ResourceBinding, details map[string]interface{}) error {
	policyID := ""
	policyVersion := ""
	mergedDetails := map[string]interface{}{"reason": reason}
	for key, value := range details {
		mergedDetails[key] = value
	}

	if binding != nil {
		policyID = binding.Label.PolicyID
		policyVersion = binding.Label.PolicyVersion
		mergedDetails["binding_profile_id"] = binding.Binding.ProfileID
		mergedDetails["binding_key_id"] = binding.Binding.KeyID
	}

	return &service.ForbiddenError{
		Reason:        reason,
		PolicyID:      policyID,
		PolicyVersion: policyVersion,
		Details:       mergedDetails,
	}
}

func bindingReasonFromError(err error) string {
	switch {
	case errors.Is(err, service.ErrBindingMissing):
		return "binding_missing"
	case errors.Is(err, service.ErrBindingCorrupted):
		return "binding_corrupted"
	default:
		return "binding_invalid"
	}
}

func logBindingFailure(logger *slog.Logger, resourceType, resourceID, reason string, details map[string]interface{}) {
	if logger == nil {
		return
	}

	args := []any{
		slog.String("resource_type", resourceType),
		slog.String("resource_id", resourceID),
		slog.String("reason", reason),
		slog.String("enforcement_layer", "repository"),
	}
	for key, value := range details {
		args = append(args, slog.Any(key, value))
	}

	logger.Warn("binding verification failed", args...)
}

type filmBindingPayload struct {
	ResourceType  string `json:"resource_type"`
	TenantID      string `json:"tenant_id"`
	ID            string `json:"id"`
	Title         string `json:"title"`
	TimeElapsedCT string `json:"time_elapsed_ct"`
}

type hallBindingPayload struct {
	ResourceType  string `json:"resource_type"`
	TenantID      string `json:"tenant_id"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	OwnerUserID   string `json:"owner_user_id"`
	CurrentFilmID string `json:"current_film_id"`
}

type spectatorBindingPayload struct {
	ResourceType     string `json:"resource_type"`
	TenantID         string `json:"tenant_id"`
	ID               string `json:"id"`
	HallID           string `json:"hall_id"`
	NameCT           string `json:"name_ct"`
	AgeCT            string `json:"age_ct"`
	ExternalIDCT     string `json:"external_id_ct"`
	ExternalIDLookup []byte `json:"external_id_lookup"`
}

func buildFilmPayload(record service.FilmRecord) filmBindingPayload {
	return filmBindingPayload{
		ResourceType:  "film",
		TenantID:      record.TenantID,
		ID:            record.ID,
		Title:         record.Title,
		TimeElapsedCT: record.TimeElapsedCT,
	}
}

func buildHallPayload(record service.HallRecord) hallBindingPayload {
	return hallBindingPayload{
		ResourceType:  "hall",
		TenantID:      record.TenantID,
		ID:            record.ID,
		Name:          record.Name,
		OwnerUserID:   record.OwnerUserID,
		CurrentFilmID: record.CurrentFilmID,
	}
}

func buildSpectatorPayload(spectator *domain.Spectator) spectatorBindingPayload {
	return spectatorBindingPayload{
		ResourceType:     "spectator",
		TenantID:         spectator.TenantID,
		ID:               spectator.ID,
		HallID:           spectator.HallID,
		NameCT:           spectator.NameCT,
		AgeCT:            spectator.AgeCT,
		ExternalIDCT:     spectator.ExternalIDCT,
		ExternalIDLookup: append([]byte(nil), spectator.ExternalIDLookup...),
	}
}

func buildFilmResource(record service.FilmRecord) service.Resource {
	return service.Resource{
		Type:     "film",
		ID:       record.ID,
		TenantID: record.TenantID,
	}
}

func buildHallResource(hall *domain.Hall) service.Resource {
	return service.Resource{
		Type:     "hall",
		ID:       hall.ID,
		TenantID: hall.TenantID,
		Labels:   append([]string(nil), hall.Labels...),
	}
}

func buildSpectatorResource(spectator *domain.Spectator) service.Resource {
	return service.Resource{
		Type:     "spectator",
		ID:       spectator.ID,
		TenantID: spectator.TenantID,
		Labels:   append([]string(nil), spectator.Labels...),
	}
}

func bindFilmRecords(records []service.FilmRecord) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}

func bindHallRecords(records []service.HallRecord) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}

func bindSpectatorRecords(records []*domain.Spectator) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}

var defaultFieldClassifications = map[string]map[string]service.Classification{
	"film": {
		"title":        service.ClassificationPublic,
		"time_elapsed": service.ClassificationSensitive,
	},
	"hall": {
		"name":            service.ClassificationPublic,
		"owner_user_id":   service.ClassificationInternal,
		"current_film_id": service.ClassificationInternal,
	},
	"spectator": {
		"name":        service.ClassificationPII,
		"age":         service.ClassificationSensitive,
		"external_id": service.ClassificationPII,
	},
}

func withAction(access service.AccessContext, action service.Action) service.AccessContext {
	access.Action = action
	return access
}

func authorize(ctx context.Context, authorizer service.Authorizer, access service.AccessContext, resource service.Resource) (service.Decision, error) {
	if authorizer == nil {
		return service.Decision{}, bindingFailureError("authorization_not_configured", nil, nil)
	}
	return authorizer.Authorize(ctx, service.PolicyInput{Access: access, Resource: resource})
}

func forbiddenFromDecision(decision service.Decision, details map[string]interface{}) error {
	merged := map[string]interface{}{}
	for key, value := range details {
		merged[key] = value
	}
	if decision.Reason != "" {
		merged["reason"] = decision.Reason
	}
	return &service.ForbiddenError{
		DecisionHash:  decision.Hash,
		Reason:        decision.Reason,
		PolicyID:      decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
		Details:       merged,
	}
}

func resourceFields(ctx context.Context, reader service.ClassificationMetadataReader, resourceType string) (map[string]service.FieldMeta, error) {
	fields := map[string]service.FieldMeta{}
	if defaults, ok := defaultFieldClassifications[resourceType]; ok {
		for fieldName, classification := range defaults {
			fields[fieldName] = service.FieldMeta{Classification: classification}
		}
	}
	if reader == nil {
		return fields, nil
	}

	classifications, err := reader.GetByResourceType(ctx, resourceType)
	if err != nil {
		return nil, err
	}
	if len(classifications) == 0 {
		return fields, nil
	}
	for _, classification := range classifications {
		fields[classification.FieldName] = service.FieldMeta{Classification: service.Classification(classification.Classification)}
	}
	return fields, nil
}

func hallPolicyResource(ctx context.Context, reader service.ClassificationMetadataReader, record service.HallRecord) (service.Resource, error) {
	fields, err := resourceFields(ctx, reader, "hall")
	if err != nil {
		return service.Resource{}, err
	}
	return service.Resource{Type: "hall", ID: record.ID, TenantID: record.TenantID, Fields: fields}, nil
}

func hallWriteResource(ctx context.Context, reader service.ClassificationMetadataReader, hall *domain.Hall) (service.Resource, error) {
	fields, err := resourceFields(ctx, reader, "hall")
	if err != nil {
		return service.Resource{}, err
	}
	return service.Resource{Type: "hall", ID: hall.ID, TenantID: hall.TenantID, Labels: append([]string(nil), hall.Labels...), Fields: fields}, nil
}

func spectatorPolicyResource(ctx context.Context, reader service.ClassificationMetadataReader, spectator *domain.Spectator) (service.Resource, error) {
	fields, err := resourceFields(ctx, reader, "spectator")
	if err != nil {
		return service.Resource{}, err
	}
	return service.Resource{Type: "spectator", ID: spectator.ID, TenantID: spectator.TenantID, Labels: append([]string(nil), spectator.Labels...), Fields: fields}, nil
}

func spectatorWriteResource(ctx context.Context, reader service.ClassificationMetadataReader, spectator *domain.Spectator) (service.Resource, error) {
	return spectatorPolicyResource(ctx, reader, spectator)
}
