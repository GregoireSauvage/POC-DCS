package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

var (
	ErrForbidden = errors.New("forbidden")
	ErrNotFound  = errors.New("not found")
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
}

type KMS interface {
	Encrypt(ctx context.Context, plaintext string) (string, error)
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

type FilmService struct {
	repo      FilmRepository
	enforcer  PolicyEnforcer
	encryptor KMS
	audit     *AuditService
}

func NewFilmService(repo FilmRepository, policyEnforcer PolicyEnforcer, kms KMS, audit *AuditService) *FilmService {
	return &FilmService{
		repo:      repo,
		enforcer:  policyEnforcer,
		encryptor: kms,
		audit:     audit,
	}
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
	return FilmOutput{
		ID:          updated.ID,
		Title:       updated.Title,
		TimeElapsed: result.TimeElapsed,
	}, pctx, nil
}
