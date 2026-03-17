package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

type hallService struct {
	secureRepo           SecureHallRepository
	authorizer           Authorizer
	classificationReader ClassificationMetadataReader
	audit                *AuditService
	perf                 PerfWriter
	runtime              RuntimeSettings
}

func NewHallService(
	secureRepo SecureHallRepository,
	authorizer Authorizer,
	classificationReader ClassificationMetadataReader,
	audit *AuditService,
	perf PerfWriter,
	runtime RuntimeSettings,
) HallService {
	return &hallService{
		secureRepo:           secureRepo,
		authorizer:           authorizer,
		classificationReader: classificationReader,
		audit:                audit,
		perf:                 perf,
		runtime:              runtime,
	}
}

// List returns all halls for the tenant with field-level enforcement
func (s *hallService) List(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
) ([]HallOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionHallRead)

	candidates, err := s.secureRepo.ListCandidates(ctx, principal.TenantID)
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
				s.writeAuditLog(ctx, principal, reqCtx, "hall.read", "hall", "", "deny", decisionHash, policyID, policyVersion, details, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.read", "hall")
			}
			return nil, pctx, ErrForbidden
		}
		return nil, pctx, fmt.Errorf("failed to list halls: %w", err)
	}

	outputs := make([]HallOutput, 0, len(candidates))
	masked := map[string]bool{}
	denied := map[string]bool{}
	decisionHash := ""
	policyID := ""
	policyVersion := ""
	for _, candidate := range candidates {
		decision, err := s.authorize(ctx, ActionHallRead, candidate.Resource)
		if err != nil {
			return nil, pctx, fmt.Errorf("authorize hall.read: %w", err)
		}
		if !decision.Allow {
			if s.audit != nil {
				s.writeAuditLog(ctx, principal, reqCtx, "hall.read", "hall", candidate.Record.ID, "deny", decision.Hash, decision.PolicyID, decision.PolicyVersion,
					map[string]interface{}{"reason": decision.Reason}, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.read", "hall")
			}
			return nil, pctx, ErrForbidden
		}

		view, err := s.secureRepo.ApplyReadDecision(ctx, candidate, decision)
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
					s.writeAuditLog(ctx, principal, reqCtx, "hall.read", "hall", candidate.Record.ID, "deny", decisionHash, policyID, policyVersion, details, nil, nil)
				}
				if s.perf != nil {
					s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.read", "hall")
				}
				return nil, pctx, ErrForbidden
			}
			return nil, pctx, fmt.Errorf("apply hall.read decision: %w", err)
		}

		outputs = append(outputs, view.Output)
		if decisionHash == "" {
			decisionHash = view.DecisionHash
			policyID = view.PolicyID
			policyVersion = view.PolicyVersion
		}
		for _, field := range view.FieldsMasked {
			masked[field] = true
		}
		for _, field := range view.FieldsDenied {
			denied[field] = true
		}
	}

	if s.audit != nil {
		s.writeAuditLog(
			ctx,
			principal,
			reqCtx,
			"hall.read",
			"hall",
			"",
			"allow",
			decisionHash,
			policyID,
			policyVersion,
			nil,
			mapKeys(masked),
			mapKeys(denied),
		)
	}

	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.read", "hall")
	}

	return outputs, pctx, nil
}

// Create creates a new hall
func (s *hallService) Create(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	input HallCreateInput,
) (HallOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionHallCreate)

	writeResource, err := BuildHallWriteResource(ctx, s.classificationReader, principal.TenantID, "", input.OwnerUserID, nil)
	if err != nil {
		return HallOutput{}, pctx, fmt.Errorf("build hall.create resource: %w", err)
	}
	writeDecision, err := s.authorize(ctx, ActionHallCreate, writeResource)
	if err != nil {
		return HallOutput{}, pctx, fmt.Errorf("authorize hall.create: %w", err)
	}
	if !writeDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "hall.create", "hall", "", "deny", writeDecision.Hash, writeDecision.PolicyID, writeDecision.PolicyVersion,
				map[string]interface{}{"reason": writeDecision.Reason}, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
		}
		return HallOutput{}, pctx, ErrForbidden
	}

	candidate, err := s.secureRepo.Create(ctx, principal.TenantID, input, writeDecision)
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
				s.writeAuditLog(ctx, principal, reqCtx, "hall.create", "hall", "", "deny", decisionHash, policyID, policyVersion, details, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
			}
			return HallOutput{}, pctx, ErrForbidden
		}
		return HallOutput{}, pctx, fmt.Errorf("failed to create hall: %w", err)
	}

	readDecision, err := s.authorize(ctx, ActionHallRead, candidate.Resource)
	if err != nil {
		return HallOutput{}, pctx, fmt.Errorf("authorize hall.read after create: %w", err)
	}
	if !readDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "hall.create", "hall", candidate.Record.ID, "deny", readDecision.Hash, readDecision.PolicyID, readDecision.PolicyVersion,
				map[string]interface{}{"reason": readDecision.Reason}, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
		}
		return HallOutput{}, pctx, ErrForbidden
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
				s.writeAuditLog(ctx, principal, reqCtx, "hall.create", "hall", candidate.Record.ID, "deny", decisionHash, policyID, policyVersion, details, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
			}
			return HallOutput{}, pctx, ErrForbidden
		}
		return HallOutput{}, pctx, fmt.Errorf("apply hall.read decision: %w", err)
	}

	if s.audit != nil {
		s.writeAuditLog(ctx, principal, reqCtx, "hall.create", "hall", fmt.Sprint(view.Output.ID), "allow", view.DecisionHash, view.PolicyID, view.PolicyVersion, nil, view.FieldsMasked, view.FieldsDenied)
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "hall.create", "hall")
	}
	return view.Output, pctx, nil
}

func (s *hallService) authorize(ctx context.Context, action Action, resource Resource) (Decision, error) {
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

func (s *hallService) writeAuditLog(
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
	fieldsMasked []string,
	fieldsDenied []string,
) {
	if s.audit == nil {
		return
	}

	_ = s.audit.WriteAudit(ctx, &domain.AuditLog{
		RequestID:     reqCtx.RequestID,
		TenantID:      principal.TenantID,
		SubjectUserID: principal.UserID,
		SubjectRole:   principal.Role,
		Action:        action,
		ResourceType:  resourceType,
		ResourceID:    resourceID,
		Outcome:       outcome,
		DecisionHash:  decisionHash,
		PolicyID:      policyID,
		PolicyVersion: policyVersion,
		Details:       details,
		FieldsMasked:  fieldsMasked,
		FieldsDenied:  fieldsDenied,
	})
}

func (s *hallService) writePerfLog(
	ctx context.Context,
	pctx *perf.Context,
	principal Principal,
	reqCtx RequestContext,
	action string,
	resourceType string,
) {
	if s.runtime == nil || s.perf == nil {
		return
	}
	metrics := pctx.Metrics()

	var pipMS, pdpMS, kmsMS, dbMS *float64
	if v, ok := metrics["pip_ms"]; ok {
		pipMS = &v
	}
	if v, ok := metrics["pdp_ms"]; ok {
		pdpMS = &v
	}
	if v, ok := metrics["kms_ms"]; ok {
		kmsMS = &v
	}
	if v, ok := metrics["db_ms"]; ok {
		dbMS = &v
	}

	_ = s.perf.Write(ctx, &domain.PerfLog{
		RequestID:     reqCtx.RequestID,
		TenantID:      principal.TenantID,
		SubjectUserID: principal.UserID,
		SubjectRole:   principal.Role,
		Action:        action,
		ResourceType:  resourceType,
		DCSEnabled:    s.runtime.DcsEnabled(),
		CacheLevel:    s.runtime.CacheLevel(),
		TotalMS:       pctx.TotalMS(),
		PIPMS:         pipMS,
		PDPMS:         pdpMS,
		KMSMS:         kmsMS,
		DBMS:          dbMS,
	})
}
