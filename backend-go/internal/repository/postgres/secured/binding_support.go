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
	Store       service.BindingStore
	Verifier    service.BindingVerifier
	Issuer      service.BindingIssuer
	LabelIssuer service.LabelIssuer
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
