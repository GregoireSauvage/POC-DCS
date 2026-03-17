package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

type FilmRepository interface {
	ListByTenant(ctx context.Context, tenantID string) ([]FilmRecord, error)
	UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (FilmRecord, error)
	Create(ctx context.Context, tenantID, title, timeElapsedCT string) (FilmRecord, error)
}

type SecureFilmRepository interface {
	ListByTenant(ctx context.Context, tenantID string) ([]FilmReadView, error)
	UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (FilmReadView, error)
	Create(ctx context.Context, tenantID, title, timeElapsedCT string) (FilmReadView, error)
}

type FilmService struct {
	repo     SecureFilmRepository
	enforcer PolicyEnforcer // Only DCS dependency (handles all crypto)
	audit    AuditWriter
	perf     PerfWriter
	runtime  RuntimeSettings
}

func NewFilmService(
	repo SecureFilmRepository,
	policyEnforcer PolicyEnforcer,
	audit AuditWriter,
	perfWriter PerfWriter,
	runtime RuntimeSettings,
) *FilmService {
	return &FilmService{
		repo:     repo,
		enforcer: policyEnforcer,
		audit:    audit,
		perf:     perfWriter,
		runtime:  runtime,
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

	// Phase 1: Authorization + Encryption (enforcer handles both)
	encrypted, err := s.enforcer.EnforceFilmCreate(ctx, principal, reqCtx, FilmCreatePlain{
		Title:       input.Title,
		TimeElapsed: input.TimeElapsed,
	})
	if err != nil {
		// Enforcer returns ErrForbidden if denied
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
		}
		// Audit log for deny (Python parity)
		if errors.Is(err, ErrForbidden) && s.audit != nil {
			// Extract decision hash and details from ForbiddenError if available
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
			s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", "", "deny", decisionHash, policyID, policyVersion, details, nil, nil, nil)
		}
		return FilmOutput{}, pctx, err
	}

	// Phase 2: Persist + secure read-shaped response
	created, err := s.repo.Create(ctx, principal.TenantID, encrypted.Title, encrypted.TimeElapsedCT)
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

	// Phase 5: Audit logging (graceful degradation if audit service is nil)
	if s.audit != nil {
		details := map[string]interface{}{
			"title":            input.Title,
			"new_time_elapsed": input.TimeElapsed,
			"film_id":          created.Output.ID,
		}
		s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", created.Output.ID, "allow", created.DecisionHash, created.PolicyID, created.PolicyVersion, details,
			created.FieldsDecrypted, created.FieldsMasked, created.FieldsDenied)
	}

	// Phase 6: Performance logging
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
	}

	return created.Output, pctx, nil
}

func (s *FilmService) List(ctx context.Context, principal Principal, reqCtx RequestContext) ([]FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)
	ctx = EnsureAccessContext(ctx, principal, reqCtx, ActionFilmRead)

	films, err := s.repo.ListByTenant(ctx, principal.TenantID)
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

	out := make([]FilmOutput, 0, len(films))

	// Collect field decisions for audit logging
	decryptedFields := make(map[string]bool)
	maskedFields := make(map[string]bool)
	deniedFields := make(map[string]bool)

	for _, film := range films {
		out = append(out, film.Output)

		// Aggregate field decisions (deduplication)
		for _, field := range film.FieldsDecrypted {
			decryptedFields[field] = true
		}
		for _, field := range film.FieldsMasked {
			maskedFields[field] = true
		}
		for _, field := range film.FieldsDenied {
			deniedFields[field] = true
		}
	}

	// Write audit log (graceful degradation if audit service is nil)
	if s.audit != nil {
		policyID := ""
		policyVersion := ""
		decisionHash := ""
		if len(films) > 0 {
			policyID = films[0].PolicyID
			policyVersion = films[0].PolicyVersion
			decisionHash = films[0].DecisionHash
		}
		s.writeAuditLog(ctx, principal, reqCtx, "film.read", "film", "", "allow", decisionHash, policyID, policyVersion, nil,
			mapKeys(decryptedFields), mapKeys(maskedFields), mapKeys(deniedFields))
	}

	// Write perf log
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

	decision, err := s.enforcer.EvaluateFilmUpdateTime(ctx, principal, reqCtx, filmID)
	if err != nil {
		return FilmOutput{}, pctx, err
	}
	if !decision.Allow {
		// Write audit log for denied update (before returning error)
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "deny", decision.DecisionHash, decision.PolicyID, decision.PolicyVersion, nil, nil, nil, nil)
		}
		return FilmOutput{}, pctx, ErrForbidden
	}

	stop := perf.Span(ctx, "kms_ms")
	ciphertext, err := s.enforcer.Encrypt(ctx, strconv.Itoa(timeElapsed))
	stop()
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("encrypt time_elapsed: %w", err)
	}

	updated, err := s.repo.UpdateTimeCiphertext(ctx, principal.TenantID, filmID, ciphertext)
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

	// Write audit log for successful update
	if s.audit != nil {
		s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "allow", decision.DecisionHash, decision.PolicyID, decision.PolicyVersion, nil, nil, nil, nil)
	}

	// Write perf log
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "film.update_time", "film")
	}

	return updated.Output, pctx, nil
}

func (s *FilmService) writePerfLog(
	ctx context.Context,
	pctx *perf.Context,
	principal Principal,
	reqCtx RequestContext,
	action string,
	resourceType string,
) {
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

// writeAuditLog writes an audit log entry for film operations.
// Errors are logged but do not fail the request (graceful degradation).
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
	// Graceful degradation: ignore errors to avoid failing user requests
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

// mapKeys extracts keys from a map as a sorted slice
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
