package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pdp"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
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
	pip       *pip.Provider
	pdp       *pdp.Engine
	applier   *pep.FilmApplier
	encryptor KMS
	audit     *AuditService
}

func NewFilmService(repo FilmRepository, provider *pip.Provider, engine *pdp.Engine, applier *pep.FilmApplier, kms KMS, audit *AuditService) *FilmService {
	return &FilmService{
		repo:      repo,
		pip:       provider,
		pdp:       engine,
		applier:   applier,
		encryptor: kms,
		audit:     audit,
	}
}

func (s *FilmService) List(ctx context.Context, principal types.Principal, reqCtx types.RequestContext) ([]FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	stop := perf.Span(ctx, "db_ms")
	films, err := s.repo.ListByTenant(ctx, principal.TenantID)
	stop()
	if err != nil {
		return nil, pctx, err
	}

	out := make([]FilmOutput, 0, len(films))
	for _, f := range films {
		pi, err := s.pip.Build(ctx, pip.Input{
			Principal:    principal,
			Action:       "film.read",
			ResourceType: "film",
			ResourceID:   f.ID,
			Request:      reqCtx,
			CryptoMeta: map[string]map[string]string{
				"time_elapsed": {"ciphertext_field": "time_elapsed_ct"},
			},
		})
		if err != nil {
			return nil, pctx, err
		}

		stop = perf.Span(ctx, "pdp_ms")
		decision, _ := s.pdp.Evaluate(pi)
		stop()

		result, err := s.applier.Apply(ctx, decision, pep.FilmRow{
			Title:         f.Title,
			TimeElapsedCT: f.TimeElapsedCT,
		})
		if err != nil {
			return nil, pctx, err
		}

		out = append(out, FilmOutput{
			ID:          f.ID,
			Title:       f.Title,
			TimeElapsed: result.Payload["time_elapsed"],
		})
	}
	return out, pctx, nil
}

func (s *FilmService) UpdateTime(
	ctx context.Context,
	principal types.Principal,
	reqCtx types.RequestContext,
	filmID string,
	timeElapsed int,
) (FilmOutput, *perf.Context, error) {
	ctx, pctx := perf.NewContext(ctx)

	piWrite, err := s.pip.Build(ctx, pip.Input{
		Principal:    principal,
		Action:       "film.update_time",
		ResourceType: "film",
		ResourceID:   filmID,
		Request:      reqCtx,
		CryptoMeta: map[string]map[string]string{
			"time_elapsed": {"ciphertext_field": "time_elapsed_ct"},
		},
	})
	if err != nil {
		return FilmOutput{}, pctx, err
	}

	stop := perf.Span(ctx, "pdp_ms")
	writeDecision, _ := s.pdp.Evaluate(piWrite)
	stop()
	if !writeDecision.Allow {
		return FilmOutput{}, pctx, ErrForbidden
	}

	stop = perf.Span(ctx, "kms_ms")
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

	piRead, err := s.pip.Build(ctx, pip.Input{
		Principal:    principal,
		Action:       "film.read",
		ResourceType: "film",
		ResourceID:   updated.ID,
		Request:      reqCtx,
		CryptoMeta: map[string]map[string]string{
			"time_elapsed": {"ciphertext_field": "time_elapsed_ct"},
		},
	})
	if err != nil {
		return FilmOutput{}, pctx, err
	}

	stop = perf.Span(ctx, "pdp_ms")
	readDecision, _ := s.pdp.Evaluate(piRead)
	stop()

	result, err := s.applier.Apply(ctx, readDecision, pep.FilmRow{
		Title:         updated.Title,
		TimeElapsedCT: updated.TimeElapsedCT,
	})
	if err != nil {
		return FilmOutput{}, pctx, err
	}
	return FilmOutput{
		ID:          updated.ID,
		Title:       updated.Title,
		TimeElapsed: result.Payload["time_elapsed"],
	}, pctx, nil
}
