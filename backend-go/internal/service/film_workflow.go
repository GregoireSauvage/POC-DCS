package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

var (
	ErrForbidden        = errors.New("forbidden")
	ErrNotFound         = errors.New("not found")
	ErrDCSNotConfigured = errors.New("DCS enforcer not configured - perf endpoints require DCS")
)

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

type FilmRepository interface {
	ListByTenant(ctx context.Context, tenantID string) ([]FilmRecord, error)
	UpdateTimeCiphertext(ctx context.Context, tenantID, filmID, ciphertext string) (FilmRecord, error)
	Create(ctx context.Context, tenantID, title, timeElapsedCT string) (FilmRecord, error)
}

type KMS interface {
	Encrypt(ctx context.Context, plaintext string) (string, error)
	Decrypt(ctx context.Context, ciphertext string) (string, error)
	GetPepper(ctx context.Context, path string) ([]byte, error)
}

type FilmService struct {
	repo      FilmRepository
	enforcer  PolicyEnforcer
	encryptor KMS
	audit     AuditWriter
	perf      PerfWriter
	runtime   RuntimeSettings
}

func NewFilmService(
	repo FilmRepository,
	policyEnforcer PolicyEnforcer,
	kms KMS,
	audit AuditWriter,
	perfWriter PerfWriter,
	runtime RuntimeSettings,
) *FilmService {
	return &FilmService{
		repo:      repo,
		enforcer:  policyEnforcer,
		encryptor: kms,
		audit:     audit,
		perf:      perfWriter,
		runtime:   runtime,
	}
}

func (s *FilmService) Create(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	input FilmCreateInput,
) (FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	// Default time_elapsed to 0 if not provided
	timeElapsed := input.TimeElapsed

	// Phase 1: Authorization (write action)
	decision, err := s.enforcer.EvaluateFilmCreate(ctx, principal, reqCtx)
	if err != nil {
		return FilmOutput{}, pctx, err
	}

	// Perf log on deny
	if !decision.Allow {
		if s.perf != nil {
			s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
		}
		// Audit log for denied create
		if s.audit != nil {
			details := map[string]interface{}{
				"reason":       decision.Reason,
				"title":        input.Title,
				"time_elapsed": timeElapsed,
			}
			s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", "", "deny", decision.DecisionHash, details, nil, nil, nil)
		}
		return FilmOutput{}, pctx, ErrForbidden
	}

	// Phase 2: Encrypt sensitive data (time_elapsed)
	stop := perf.Span(ctx, "kms_ms")
	ciphertext, err := s.encryptor.Encrypt(ctx, strconv.Itoa(timeElapsed))
	stop()
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("encrypt time_elapsed: %w", err)
	}

	// Phase 3: Persist to database
	stop = perf.Span(ctx, "db_ms")
	created, err := s.repo.Create(ctx, principal.TenantID, input.Title, ciphertext)
	stop()
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("create film: %w", err)
	}

	// Phase 4: Apply READ policy to response (read-shaped response pattern)
	result, err := s.enforcer.EnforceFilmRead(ctx, principal, reqCtx, FilmReadInput{
		FilmID:        created.ID,
		Title:         created.Title,
		TimeElapsedCT: created.TimeElapsedCT,
	})
	if err != nil {
		return FilmOutput{}, pctx, err
	}

	// Phase 5: Audit logging (graceful degradation if audit service is nil)
	if s.audit != nil {
		details := map[string]interface{}{
			"reason":           decision.Reason,
			"title":            input.Title,
			"new_time_elapsed": timeElapsed,
			"film_id":          created.ID,
		}
		s.writeAuditLog(ctx, principal, reqCtx, "film.create", "film", created.ID, "allow", decision.DecisionHash, details,
			result.FieldsDecrypted, result.FieldsMasked, result.FieldsDenied)
	}

	// Phase 6: Performance logging
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "film.create", "film")
	}

	return FilmOutput{
		ID:          created.ID,
		Title:       created.Title,
		TimeElapsed: result.TimeElapsed,
	}, pctx, nil
}

func (s *FilmService) List(ctx context.Context, principal Principal, reqCtx RequestContext) ([]FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	stop := perf.Span(ctx, "db_ms")
	films, err := s.repo.ListByTenant(ctx, principal.TenantID)
	stop()
	if err != nil {
		return nil, pctx, err
	}

	out := make([]FilmOutput, 0, len(films))

	// Collect field decisions for audit logging
	decryptedFields := make(map[string]bool)
	maskedFields := make(map[string]bool)
	deniedFields := make(map[string]bool)

	for _, f := range films {
		result, err := s.enforcer.EnforceFilmRead(ctx, principal, reqCtx, FilmReadInput{
			FilmID:        f.ID,
			Title:         f.Title,
			TimeElapsedCT: f.TimeElapsedCT,
		})
		if err != nil {
			return nil, pctx, err
		}

		out = append(out, FilmOutput{
			ID:          f.ID,
			Title:       f.Title,
			TimeElapsed: result.TimeElapsed,
		})

		// Aggregate field decisions (deduplication)
		for _, field := range result.FieldsDecrypted {
			decryptedFields[field] = true
		}
		for _, field := range result.FieldsMasked {
			maskedFields[field] = true
		}
		for _, field := range result.FieldsDenied {
			deniedFields[field] = true
		}
	}

	// Write audit log (graceful degradation if audit service is nil)
	if s.audit != nil {
		s.writeAuditLog(ctx, principal, reqCtx, "film.read", "film", "", "allow", "", nil,
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

	decision, err := s.enforcer.EvaluateFilmUpdateTime(ctx, principal, reqCtx, filmID)
	if err != nil {
		return FilmOutput{}, pctx, err
	}
	if !decision.Allow {
		// Write audit log for denied update (before returning error)
		if s.audit != nil {
			s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "deny", decision.DecisionHash, nil, nil, nil, nil)
		}
		return FilmOutput{}, pctx, ErrForbidden
	}

	stop := perf.Span(ctx, "kms_ms")
	ciphertext, err := s.encryptor.Encrypt(ctx, strconv.Itoa(timeElapsed))
	stop()
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("encrypt time_elapsed: %w", err)
	}

	stop = perf.Span(ctx, "db_ms")
	updated, err := s.repo.UpdateTimeCiphertext(ctx, principal.TenantID, filmID, ciphertext)
	stop()
	if err != nil {
		return FilmOutput{}, pctx, fmt.Errorf("%w: %v", ErrNotFound, err)
	}

	result, err := s.enforcer.EnforceFilmRead(ctx, principal, reqCtx, FilmReadInput{
		FilmID:        updated.ID,
		Title:         updated.Title,
		TimeElapsedCT: updated.TimeElapsedCT,
	})
	if err != nil {
		return FilmOutput{}, pctx, err
	}

	// Write audit log for successful update
	if s.audit != nil {
		s.writeAuditLog(ctx, principal, reqCtx, "film.update_time", "film", filmID, "allow", decision.DecisionHash, nil, nil, nil, nil)
	}

	// Write perf log
	if s.perf != nil {
		s.writePerfLog(ctx, pctx, principal, reqCtx, "film.update_time", "film")
	}

	return FilmOutput{
		ID:          updated.ID,
		Title:       updated.Title,
		TimeElapsed: result.TimeElapsed,
	}, pctx, nil
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
