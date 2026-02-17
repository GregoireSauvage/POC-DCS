package service

import (
	"context"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

const defaultPepperPath = "secret/dcs" // Python parity: config.VAULT_KV_PEPPER_PATH

// SpectatorService provides spectator business operations
type SpectatorService struct {
	repo       SpectatorRepository
	hallRepo   HallRepository
	kms        KMS
	enforcer   PolicyEnforcer
	audit      AuditWriter
	perf       PerfWriter
	runtime    RuntimeSettings
	pepperPath string
}

// NewSpectatorService creates a new spectator service
func NewSpectatorService(
	repo SpectatorRepository,
	hallRepo HallRepository,
	kms KMS,
	enforcer PolicyEnforcer,
	audit AuditWriter,
	perf PerfWriter,
	runtime RuntimeSettings,
	pepperPath string,
) *SpectatorService {
	if pepperPath == "" {
		pepperPath = defaultPepperPath
	}
	return &SpectatorService{
		repo:       repo,
		hallRepo:   hallRepo,
		kms:        kms,
		enforcer:   enforcer,
		audit:      audit,
		perf:       perf,
		runtime:    runtime,
		pepperPath: pepperPath,
	}
}

// Create creates a new spectator with encrypted PII fields
func (s *SpectatorService) Create(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	input SpectatorCreateInput,
) (SpectatorOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	// 1. Validate hall exists
	hall, err := s.hallRepo.FindByID(ctx, principal.TenantID, input.HallID)
	if err != nil {
		return SpectatorOutput{}, pctx, err
	}
	if hall == nil {
		return SpectatorOutput{}, pctx, ErrNotFound
	}

	// 2. Evaluate spectator.create policy
	decision, err := s.enforcer.EvaluateSpectatorCreate(ctx, principal, reqCtx, hall.OwnerUserID)
	if err != nil {
		return SpectatorOutput{}, pctx, err
	}
	if !decision.Allow {
		// Audit + perf logging on deny (Python parity)
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "spectator.create", "spectator", "", "deny",
				decision.DecisionHash, nil, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "spectator.create", "spectator")
		}
		return SpectatorOutput{}, pctx, ErrForbidden
	}

	// 3. Encrypt PII fields
	nameCT, err := s.kms.Encrypt(ctx, input.Name)
	if err != nil {
		return SpectatorOutput{}, pctx, fmt.Errorf("encrypt name: %w", err)
	}
	ageCT, err := s.kms.Encrypt(ctx, strconv.Itoa(input.Age))
	if err != nil {
		return SpectatorOutput{}, pctx, fmt.Errorf("encrypt age: %w", err)
	}
	externalIDCT, err := s.kms.Encrypt(ctx, input.ExternalID)
	if err != nil {
		return SpectatorOutput{}, pctx, fmt.Errorf("encrypt external_id: %w", err)
	}

	// 4. Compute HMAC lookup for searchable encryption
	pepper, err := s.kms.GetPepper(ctx, s.pepperPath)
	if err != nil {
		return SpectatorOutput{}, pctx, fmt.Errorf("get pepper: %w", err)
	}
	normalized := kms.NormalizeExternalID(input.ExternalID)
	lookup := kms.ComputeHMACLookup(pepper, normalized)

	// 5. Create spectator entity
	spectatorID := uuid.New().String()
	spectator := &domain.Spectator{
		TenantID:         principal.TenantID,
		ID:               spectatorID,
		HallID:           input.HallID,
		NameCT:           nameCT,
		AgeCT:            ageCT,
		ExternalIDCT:     externalIDCT,
		ExternalIDLookup: lookup,
	}

	// 6. Insert into DB
	if err := s.repo.Create(ctx, spectator); err != nil {
		return SpectatorOutput{}, pctx, err
	}

	// 7. Apply read policy (read-shaped response - Python parity)
	result, err := s.enforcer.EnforceSpectatorRead(ctx, principal, reqCtx, SpectatorReadInput{
		SpectatorID:  spectator.ID,
		HallID:       spectator.HallID,
		NameCT:       spectator.NameCT,
		AgeCT:        spectator.AgeCT,
		ExternalIDCT: spectator.ExternalIDCT,
	})
	if err != nil {
		return SpectatorOutput{}, pctx, err
	}

	// 8. Mask spectator ID (conditional on DCS mode - Python parity)
	// Python: str(sp.id) if (p.role == "admin" or not dcs_enabled()) else mask_uuid(str(sp.id))
	var spectatorIDOutput interface{} = spectator.ID
	if s.runtime.DcsEnabled() && principal.Role != "admin" {
		spectatorIDOutput = pep.MaskUUID(spectator.ID)
	}

	// 9. Audit + Perf (with details - Python parity line 141)
	if s.audit != nil {
		details := map[string]interface{}{"hall_id": input.HallID}
		s.writeAuditLog(ctx, principal, reqCtx, "spectator.create", "spectator",
			spectator.ID, "allow", decision.DecisionHash, details,
			result.FieldsDecrypted, result.FieldsMasked, result.FieldsDenied)
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "spectator.create", "spectator")
	}

	return SpectatorOutput{
		ID:         spectatorIDOutput,
		HallID:     spectator.HallID,
		Name:       result.Name,
		Age:        result.Age,
		ExternalID: result.ExternalID,
	}, pctx, nil
}

// Search searches spectators by external_id using HMAC lookup
func (s *SpectatorService) Search(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	externalID string,
) ([]SpectatorOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	// 1. Evaluate search.spectator policy
	decision, err := s.enforcer.EvaluateSpectatorSearch(ctx, principal, reqCtx)
	if err != nil {
		return nil, pctx, err
	}
	if !decision.Allow {
		// Audit + perf logging on deny
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "search.spectator", "spectator", "", "deny",
				decision.DecisionHash, nil, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "search.spectator", "spectator")
		}
		return nil, pctx, ErrForbidden
	}

	// 2. Compute HMAC lookup
	pepper, err := s.kms.GetPepper(ctx, s.pepperPath)
	if err != nil {
		return nil, pctx, fmt.Errorf("get pepper: %w", err)
	}
	normalized := kms.NormalizeExternalID(externalID)
	lookup := kms.ComputeHMACLookup(pepper, normalized)

	// 3. Query by lookup
	spectators, err := s.repo.FindByExternalIDLookup(ctx, principal.TenantID, lookup)
	if err != nil {
		return nil, pctx, err
	}

	// 4. Apply read policy to each result
	out := make([]SpectatorOutput, 0, len(spectators))
	for _, sp := range spectators {
		result, err := s.enforcer.EnforceSpectatorRead(ctx, principal, reqCtx, SpectatorReadInput{
			SpectatorID:  sp.ID,
			HallID:       sp.HallID,
			NameCT:       sp.NameCT,
			AgeCT:        sp.AgeCT,
			ExternalIDCT: sp.ExternalIDCT,
		})
		if err != nil {
			return nil, pctx, err
		}

		// Mask spectator ID for non-admin when DCS enabled
		var spectatorIDOutput interface{} = sp.ID
		if s.runtime.DcsEnabled() && principal.Role != "admin" {
			spectatorIDOutput = pep.MaskUUID(sp.ID)
		}

		out = append(out, SpectatorOutput{
			ID:         spectatorIDOutput,
			HallID:     sp.HallID,
			Name:       result.Name,
			Age:        result.Age,
			ExternalID: result.ExternalID,
		})
	}

	// 5. Audit + Perf (with matches count - Python parity line 286)
	if s.audit != nil {
		details := map[string]interface{}{"matches": len(out)}
		s.writeAuditLog(ctx, principal, reqCtx, "search.spectator", "spectator", "", "allow",
			decision.DecisionHash, details, nil, nil, nil)
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "search.spectator", "spectator")
	}

	return out, pctx, nil
}

// writeAuditLog writes an audit log entry
func (s *SpectatorService) writeAuditLog(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	action string,
	resourceType string,
	resourceID string,
	outcome string,
	decisionHash string,
	details map[string]interface{},
	fieldsDecrypted []string,
	fieldsMasked []string,
	fieldsDenied []string,
) {
	if s.audit == nil {
		return
	}

	log := &domain.AuditLog{
		RequestID:       reqCtx.RequestID,
		TenantID:        principal.TenantID,
		SubjectUserID:   principal.UserID,
		SubjectRole:     principal.Role,
		Action:          action,
		ResourceType:    resourceType,
		ResourceID:      resourceID,
		Outcome:         outcome,
		DecisionHash:    decisionHash,
		Details:         details,
		FieldsDecrypted: fieldsDecrypted,
		FieldsMasked:    fieldsMasked,
		FieldsDenied:    fieldsDenied,
	}

	_ = s.audit.WriteAudit(ctx, log)
}

// writePerfLog writes a performance log entry
func (s *SpectatorService) writePerfLog(
	ctx context.Context,
	pctx *perf.Context,
	principal Principal,
	reqCtx RequestContext,
	action string,
	resourceType string,
) {
	if s.perf == nil {
		return
	}

	log := &domain.PerfLog{
		RequestID:     reqCtx.RequestID,
		TenantID:      principal.TenantID,
		SubjectUserID: principal.UserID,
		SubjectRole:   principal.Role,
		Action:        action,
		ResourceType:  resourceType,
		DCSEnabled:    s.runtime.DcsEnabled(),
		CacheLevel:    s.runtime.CacheLevel(),
		TotalMS:       pctx.TotalMS(),
	}

	_ = s.perf.Write(ctx, log)
}
