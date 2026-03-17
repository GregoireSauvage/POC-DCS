package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

// SpectatorService provides spectator business operations
type SpectatorService struct {
	secureRepo           SecureSpectatorRepository
	hallRepo             HallRepository
	authorizer           Authorizer
	classificationReader ClassificationMetadataReader
	audit                AuditWriter
	perf                 PerfWriter
	runtime              RuntimeSettings
}

func NewSpectatorService(
	secureRepo SecureSpectatorRepository,
	hallRepo HallRepository,
	authorizer Authorizer,
	classificationReader ClassificationMetadataReader,
	audit AuditWriter,
	perf PerfWriter,
	runtime RuntimeSettings,
) *SpectatorService {
	return &SpectatorService{
		secureRepo:           secureRepo,
		hallRepo:             hallRepo,
		authorizer:           authorizer,
		classificationReader: classificationReader,
		audit:                audit,
		perf:                 perf,
		runtime:              runtime,
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
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionSpectatorCreate)

	hall, err := s.hallRepo.FindByID(ctx, principal.TenantID, input.HallID)
	if err != nil {
		return SpectatorOutput{}, pctx, err
	}
	if hall == nil {
		return SpectatorOutput{}, pctx, ErrNotFound
	}

	writeResource, err := BuildSpectatorWriteResource(ctx, s.classificationReader, principal.TenantID, "", hall.OwnerUserID, nil)
	if err != nil {
		return SpectatorOutput{}, pctx, fmt.Errorf("build spectator.create resource: %w", err)
	}
	writeDecision, err := s.authorize(ctx, ActionSpectatorCreate, writeResource)
	if err != nil {
		return SpectatorOutput{}, pctx, fmt.Errorf("authorize spectator.create: %w", err)
	}
	if !writeDecision.Allow {
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "spectator.create", "spectator")
		}
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "spectator.create", "spectator", "", "deny", writeDecision.Hash, writeDecision.PolicyID, writeDecision.PolicyVersion,
				map[string]interface{}{"reason": writeDecision.Reason}, nil, nil, nil)
		}
		return SpectatorOutput{}, pctx, ErrForbidden
	}

	candidate, err := s.secureRepo.Create(ctx, principal.TenantID, input, writeDecision)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			if s.audit != nil {
				var forbiddenErr *ForbiddenError
				decisionHash := ""
				details := map[string]interface{}(nil)
				policyID := ""
				policyVersion := ""
				if errors.As(err, &forbiddenErr) {
					decisionHash = forbiddenErr.DecisionHash
					details = forbiddenErr.Details
					policyID = forbiddenErr.PolicyID
					policyVersion = forbiddenErr.PolicyVersion
				}
				s.writeAuditLog(ctx, principal, reqCtx, "spectator.create", "spectator", "", "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "spectator.create", "spectator")
			}
			return SpectatorOutput{}, pctx, ErrForbidden
		}
		return SpectatorOutput{}, pctx, err
	}

	readDecision, err := s.authorize(ctx, ActionSpectatorRead, candidate.Resource)
	if err != nil {
		return SpectatorOutput{}, pctx, fmt.Errorf("authorize spectator.read after create: %w", err)
	}
	if !readDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "spectator.create", "spectator", candidate.Record.ID, "deny", readDecision.Hash, readDecision.PolicyID, readDecision.PolicyVersion,
				map[string]interface{}{"reason": readDecision.Reason}, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "spectator.create", "spectator")
		}
		return SpectatorOutput{}, pctx, ErrForbidden
	}

	view, err := s.secureRepo.ApplyReadDecision(ctx, candidate, readDecision)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			if s.audit != nil {
				var forbiddenErr *ForbiddenError
				decisionHash := ""
				details := map[string]interface{}(nil)
				policyID := ""
				policyVersion := ""
				if errors.As(err, &forbiddenErr) {
					decisionHash = forbiddenErr.DecisionHash
					details = forbiddenErr.Details
					policyID = forbiddenErr.PolicyID
					policyVersion = forbiddenErr.PolicyVersion
				}
				s.writeAuditLog(ctx, principal, reqCtx, "spectator.create", "spectator", candidate.Record.ID, "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "spectator.create", "spectator")
			}
			return SpectatorOutput{}, pctx, ErrForbidden
		}
		return SpectatorOutput{}, pctx, fmt.Errorf("apply spectator.read decision: %w", err)
	}

	if s.audit != nil {
		details := map[string]interface{}{"hall_id": input.HallID}
		s.writeAuditLog(ctx, principal, reqCtx, "spectator.create", "spectator",
			fmt.Sprint(view.Output.ID), "allow", view.DecisionHash, view.PolicyID, view.PolicyVersion, details,
			view.FieldsDecrypted, view.FieldsMasked, view.FieldsDenied)
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "spectator.create", "spectator")
	}

	return view.Output, pctx, nil
}

// Search searches spectators by external_id using HMAC lookup
func (s *SpectatorService) Search(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	externalID string,
) ([]SpectatorOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionSearchSpectator)

	searchResource, err := BuildSpectatorSearchResource(ctx, s.classificationReader, principal.TenantID)
	if err != nil {
		return nil, pctx, fmt.Errorf("build search.spectator resource: %w", err)
	}
	searchDecision, err := s.authorize(ctx, ActionSearchSpectator, searchResource)
	if err != nil {
		return nil, pctx, fmt.Errorf("authorize search.spectator: %w", err)
	}
	if !searchDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "search.spectator", "spectator", "", "deny",
				searchDecision.Hash, searchDecision.PolicyID, searchDecision.PolicyVersion, map[string]interface{}{"reason": searchDecision.Reason}, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "search.spectator", "spectator")
		}
		return nil, pctx, ErrForbidden
	}

	candidates, err := s.secureRepo.SearchCandidatesByExternalID(ctx, principal.TenantID, externalID, searchDecision)
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			if s.audit != nil {
				var forbiddenErr *ForbiddenError
				decisionHash := ""
				policyID := ""
				policyVersion := ""
				details := map[string]interface{}(nil)
				if errors.As(err, &forbiddenErr) {
					decisionHash = forbiddenErr.DecisionHash
					policyID = forbiddenErr.PolicyID
					policyVersion = forbiddenErr.PolicyVersion
					details = forbiddenErr.Details
				}
				s.writeAuditLog(ctx, principal, reqCtx, "search.spectator", "spectator", "", "deny",
					decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "search.spectator", "spectator")
			}
			return nil, pctx, ErrForbidden
		}
		return nil, pctx, err
	}

	out := make([]SpectatorOutput, 0, len(candidates))
	policyID := ""
	policyVersion := ""
	decisionHash := ""
	for _, candidate := range candidates {
		readDecision, err := s.authorize(ctx, ActionSpectatorRead, candidate.Resource)
		if err != nil {
			return nil, pctx, fmt.Errorf("authorize spectator.read: %w", err)
		}
		if !readDecision.Allow {
			if s.audit != nil {
				s.writeAuditLog(ctx, principal, reqCtx, "search.spectator", "spectator", candidate.Record.ID, "deny",
					readDecision.Hash, readDecision.PolicyID, readDecision.PolicyVersion, map[string]interface{}{"reason": readDecision.Reason}, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "search.spectator", "spectator")
			}
			return nil, pctx, ErrForbidden
		}

		view, err := s.secureRepo.ApplyReadDecision(ctx, candidate, readDecision)
		if err != nil {
			if errors.Is(err, ErrForbidden) {
				if s.audit != nil {
					var forbiddenErr *ForbiddenError
					decisionHash := ""
					policyID := ""
					policyVersion := ""
					details := map[string]interface{}(nil)
					if errors.As(err, &forbiddenErr) {
						decisionHash = forbiddenErr.DecisionHash
						policyID = forbiddenErr.PolicyID
						policyVersion = forbiddenErr.PolicyVersion
						details = forbiddenErr.Details
					}
					s.writeAuditLog(ctx, principal, reqCtx, "search.spectator", "spectator", candidate.Record.ID, "deny",
						decisionHash, policyID, policyVersion, details, nil, nil, nil)
				}
				if s.perf != nil {
					s.writePerfLog(ctx, pctx, principal, reqCtx, "search.spectator", "spectator")
				}
				return nil, pctx, ErrForbidden
			}
			return nil, pctx, fmt.Errorf("apply spectator.read decision: %w", err)
		}
		out = append(out, view.Output)
		if decisionHash == "" {
			policyID = view.PolicyID
			policyVersion = view.PolicyVersion
			decisionHash = view.DecisionHash
		}
	}

	if s.audit != nil {
		details := map[string]interface{}{"matches": len(out)}
		s.writeAuditLog(ctx, principal, reqCtx, "search.spectator", "spectator", "", "allow",
			decisionHash, policyID, policyVersion, details, nil, nil, nil)
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "search.spectator", "spectator")
	}

	return out, pctx, nil
}

func (s *SpectatorService) authorize(ctx context.Context, action Action, resource Resource) (Decision, error) {
	if s.authorizer == nil {
		return Decision{}, ErrForbidden
	}
	access, ok := AccessContextFromContext(ctx)
	if !ok {
		return Decision{}, &ForbiddenError{Reason: "missing_access_context"}
	}
	access.Action = action
	return s.authorizer.Authorize(ctx, PolicyInput{Access: access, Resource: resource})
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
	policyID string,
	policyVersion string,
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
		PolicyID:        policyID,
		PolicyVersion:   policyVersion,
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
	if s.perf == nil || s.runtime == nil {
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
