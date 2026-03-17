package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

var (
	ErrForbidden        = errors.New("forbidden")
	ErrNotFound         = errors.New("not found")
	ErrDCSNotConfigured = errors.New("DCS enforcer not configured - perf endpoints require DCS")
)

// ForbiddenError wraps a forbidden error with additional context for audit logging
type ForbiddenError struct {
	DecisionHash  string
	Reason        string
	Details       map[string]interface{}
	PolicyID      string
	PolicyVersion string
}

func (e *ForbiddenError) Error() string {
	return "forbidden"
}

func (e *ForbiddenError) Is(target error) bool {
	return target == ErrForbidden
}

type FilmRecord struct {
	TenantID      string
	ID            string
	Title         string
	TimeElapsedCT string
}

type FilmOutput struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	TimeElapsed interface{} `json:"time_elapsed"`
}

type FilmReadView struct {
	Output          FilmOutput
	FieldsDecrypted []string
	FieldsMasked    []string
	FieldsDenied    []string
	DecisionHash    string
	PolicyID        string
	PolicyVersion   string
}

type FilmReadCandidate struct {
	Record   FilmRecord
	Resource Resource
}

type FilmCreateInput struct {
	Title       string
	TimeElapsed int
}

type FilmRepository interface {
	ListByTenant(ctx context.Context, tenantID string) ([]FilmRecord, error)
	UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (FilmRecord, error)
	Create(ctx context.Context, tenantID, title, timeElapsedCT string) (FilmRecord, error)
}

type SecureFilmRepository interface {
	ListCandidates(ctx context.Context, tenantID string) ([]FilmReadCandidate, error)
	Create(ctx context.Context, tenantID string, input FilmCreateInput, decision Decision) (FilmReadCandidate, error)
	UpdateTime(ctx context.Context, tenantID, filmID string, timeElapsed int, decision Decision) (FilmReadCandidate, error)
	ApplyReadDecision(ctx context.Context, candidate FilmReadCandidate, decision Decision) (FilmReadView, error)
}

type FilmService struct {
	repo                 SecureFilmRepository
	authorizer           Authorizer
	classificationReader ClassificationMetadataReader
	audit                AuditWriter
	perf                 PerfWriter
	runtime              RuntimeSettings
}

func NewFilmService(
	repo SecureFilmRepository,
	authorizer Authorizer,
	classificationReader ClassificationMetadataReader,
	audit AuditWriter,
	perfWriter PerfWriter,
	runtime RuntimeSettings,
) *FilmService {
	return &FilmService{
		repo:                 repo,
		authorizer:           authorizer,
		classificationReader: classificationReader,
		audit:                audit,
		perf:                 perfWriter,
		runtime:              runtime,
	}
}

func (s *FilmService) Create(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	input FilmCreateInput,
) (FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionFilmCreate)

	writeResource, err := BuildFilmWriteResource(ctx, s.classificationReader, principal.TenantID, "")
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("build film.create resource: %w", err)
	}
	writeDecision, err := s.authorize(ctx, ActionFilmCreate, writeResource)
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("authorize film.create: %w", err)
	}
	if !writeDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", "", "deny", writeDecision.Hash, writeDecision.PolicyID, writeDecision.PolicyVersion,
				map[string]interface{}{"reason": writeDecision.Reason}, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
		}
		return FilmOutput{}, pctx, ErrForbidden
	}

	candidate, err := s.repo.Create(ctx, principal.TenantID, input, writeDecision)
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
				s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", "", "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
			}
			return FilmOutput{}, pctx, ErrForbidden
		}
		return FilmOutput{}, pctx, fmt.Errorf("create film: %w", err)
	}

	readDecision, err := s.authorize(ctx, ActionFilmRead, candidate.Resource)
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("authorize film.read after create: %w", err)
	}
	if !readDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", candidate.Record.ID, "deny", readDecision.Hash, readDecision.PolicyID, readDecision.PolicyVersion,
				map[string]interface{}{"reason": readDecision.Reason}, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
		}
		return FilmOutput{}, pctx, ErrForbidden
	}

	created, err := s.repo.ApplyReadDecision(ctx, candidate, readDecision)
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
				s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", candidate.Record.ID, "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
			}
			return FilmOutput{}, pctx, ErrForbidden
		}
		return FilmOutput{}, pctx, fmt.Errorf("shape created film: %w", err)
	}

	if s.audit != nil {
		details := map[string]interface{}{
			"title":            input.Title,
			"new_time_elapsed": input.TimeElapsed,
			"film_id":          created.Output.ID,
		}
		s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", created.Output.ID, "allow", created.DecisionHash, created.PolicyID, created.PolicyVersion, details,
			created.FieldsDecrypted, created.FieldsMasked, created.FieldsDenied)
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
	}

	return created.Output, pctx, nil
}

func (s *FilmService) List(ctx context.Context, principal Principal, reqCtx RequestContext) ([]FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionFilmRead)

	candidates, err := s.repo.ListCandidates(ctx, principal.TenantID)
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
				s.writeAuditLog(ctx, principal, reqCtx, "film.read", "film", "", "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "film.read", "film")
			}
			return nil, pctx, ErrForbidden
		}
		return nil, pctx, err
	}

	views := make([]FilmReadView, 0, len(candidates))
	out := make([]FilmOutput, 0, len(candidates))
	decryptedFields := make(map[string]bool)
	maskedFields := make(map[string]bool)
	deniedFields := make(map[string]bool)

	for _, candidate := range candidates {
		decision, err := s.authorize(ctx, ActionFilmRead, candidate.Resource)
		if err != nil {
			return nil, pctx, fmt.Errorf("authorize film.read: %w", err)
		}
		if !decision.Allow {
			if s.audit != nil {
				s.writeAuditLog(ctx, principal, reqCtx, "film.read", "film", candidate.Record.ID, "deny", decision.Hash, decision.PolicyID, decision.PolicyVersion,
					map[string]interface{}{"reason": decision.Reason}, nil, nil, nil)
			}
			if s.perf != nil {
				s.writePerfLog(ctx, pctx, principal, reqCtx, "film.read", "film")
			}
			return nil, pctx, ErrForbidden
		}

		view, err := s.repo.ApplyReadDecision(ctx, candidate, decision)
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
					s.writeAuditLog(ctx, principal, reqCtx, "film.read", "film", candidate.Record.ID, "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
				}
				if s.perf != nil {
					s.writePerfLog(ctx, pctx, principal, reqCtx, "film.read", "film")
				}
				return nil, pctx, ErrForbidden
			}
			return nil, pctx, fmt.Errorf("apply film.read decision: %w", err)
		}

		views = append(views, view)
		out = append(out, view.Output)
		for _, field := range view.FieldsDecrypted {
			decryptedFields[field] = true
		}
		for _, field := range view.FieldsMasked {
			maskedFields[field] = true
		}
		for _, field := range view.FieldsDenied {
			deniedFields[field] = true
		}
	}

	if s.audit != nil {
		policyID := ""
		policyVersion := ""
		decisionHash := ""
		if len(views) > 0 {
			policyID = views[0].PolicyID
			policyVersion = views[0].PolicyVersion
			decisionHash = views[0].DecisionHash
		}
		s.writeAuditLog(ctx, principal, reqCtx, "film.read", "film", "", "allow", decisionHash, policyID, policyVersion, nil,
			mapKeys(decryptedFields), mapKeys(maskedFields), mapKeys(deniedFields))
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "film.read", "film")
	}

	return out, pctx, nil
}

func (s *FilmService) UpdateTime(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	filmID string,
	timeElapsed int,
) (FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionFilmUpdateTime)

	writeResource, err := BuildFilmWriteResource(ctx, s.classificationReader, principal.TenantID, filmID)
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("build film.update_time resource: %w", err)
	}
	writeDecision, err := s.authorize(ctx, ActionFilmUpdateTime, writeResource)
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("authorize film.update_time: %w", err)
	}
	if !writeDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "deny", writeDecision.Hash, writeDecision.PolicyID, writeDecision.PolicyVersion,
				map[string]interface{}{"reason": writeDecision.Reason}, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "film.update_time", "film")
		}
		return FilmOutput{}, pctx, ErrForbidden
	}

	candidate, err := s.repo.UpdateTime(ctx, principal.TenantID, filmID, timeElapsed, writeDecision)
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
				s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			return FilmOutput{}, pctx, err
		}
		if errors.Is(err, ErrNotFound) || strings.Contains(strings.ToLower(err.Error()), "not found") {
			return FilmOutput{}, pctx, fmt.Errorf("%w: %v", ErrNotFound, err)
		}
		return FilmOutput{}, pctx, err
	}

	readDecision, err := s.authorize(ctx, ActionFilmRead, candidate.Resource)
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("authorize film.read after update: %w", err)
	}
	if !readDecision.Allow {
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "deny", readDecision.Hash, readDecision.PolicyID, readDecision.PolicyVersion,
				map[string]interface{}{"reason": readDecision.Reason}, nil, nil, nil)
		}
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "film.update_time", "film")
		}
		return FilmOutput{}, pctx, ErrForbidden
	}

	updated, err := s.repo.ApplyReadDecision(ctx, candidate, readDecision)
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
				s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
			}
			return FilmOutput{}, pctx, ErrForbidden
		}
		return FilmOutput{}, pctx, fmt.Errorf("shape updated film: %w", err)
	}

	if s.audit != nil {
		details := map[string]interface{}{"new_time_elapsed": timeElapsed}
		s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "allow", updated.DecisionHash, updated.PolicyID, updated.PolicyVersion, details,
			updated.FieldsDecrypted, updated.FieldsMasked, updated.FieldsDenied)
	}
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "film.update_time", "film")
	}

	return updated.Output, pctx, nil
}

func (s *FilmService) authorize(ctx context.Context, action Action, resource Resource) (Decision, error) {
	if s.authorizer == nil {
		return Decision{}, fmt.Errorf("film authorizer not configured")
	}

	access, ok := AccessContextFromContext(ctx)
	if !ok {
		return Decision{}, &ForbiddenError{Reason: "missing_access_context"}
	}
	access.Action = action

	return s.authorizer.Authorize(ctx, PolicyInput{
		Access:   access,
		Resource: resource,
	})
}

func (s *FilmService) writePerfLog(
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

func (s *FilmService) writeAuditLog(
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
	_ = s.audit.WriteAudit(ctx, &domain.AuditLog{
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
	})
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
