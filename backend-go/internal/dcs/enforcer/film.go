package enforcer

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pdp"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type DcsEnforcer struct {
	pip              *pip.Provider
	pdp              *pdp.Engine
	filmApplier      *pep.FilmApplier
	spectatorApplier *pep.SpectatorApplier
	kms              pep.Decryptor // For creating appliers on-the-fly
}

func New(pipProvider *pip.Provider, pdpEngine *pdp.Engine, filmApplier *pep.FilmApplier, spectatorApplier *pep.SpectatorApplier, kms pep.Decryptor) *DcsEnforcer {
	return &DcsEnforcer{
		pip:              pipProvider,
		pdp:              pdpEngine,
		filmApplier:      filmApplier,
		spectatorApplier: spectatorApplier,
		kms:              kms,
	}
}

func (e *DcsEnforcer) EvaluateFilmCreate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
) (service.AuthorizationDecision, error) {
	decision, err := e.evaluate(ctx, principal, reqCtx, "film.create", "")
	if err != nil {
		return service.AuthorizationDecision{}, err
	}
	return service.AuthorizationDecision{
		Allow:        decision.Allow,
		Reason:       decision.Reason,
		DecisionHash: decision.Hash,
	}, nil
}

func (e *DcsEnforcer) EvaluateFilmUpdateTime(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	filmID string,
) (service.AuthorizationDecision, error) {
	decision, err := e.evaluate(ctx, principal, reqCtx, "film.update_time", filmID)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}
	return service.AuthorizationDecision{
		Allow:        decision.Allow,
		Reason:       decision.Reason,
		DecisionHash: decision.Hash,
	}, nil
}

func (e *DcsEnforcer) EvaluateAuditRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
) (service.AuthorizationDecision, error) {
	pi, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "audit.read",
		ResourceType: "audit",
		ResourceID:   "audit",
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	stop := perf.Span(ctx, "pdp_ms")
	decision, _ := e.pdp.Evaluate(pi)
	stop()

	return service.AuthorizationDecision{
		Allow:  decision.Allow,
		Reason: decision.Reason,
	}, nil
}

func (e *DcsEnforcer) EvaluatePerfRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
) (service.AuthorizationDecision, error) {
	pi, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "perf.read",
		ResourceType: "perf",
		ResourceID:   "perf",
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	stop := perf.Span(ctx, "pdp_ms")
	decision, _ := e.pdp.Evaluate(pi)
	stop()

	return service.AuthorizationDecision{
		Allow:  decision.Allow,
		Reason: decision.Reason,
	}, nil
}

func (e *DcsEnforcer) EnforceFilmRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	film service.FilmReadInput,
) (service.FilmReadResult, error) {
	decision, err := e.evaluate(ctx, principal, reqCtx, "film.read", film.FilmID)
	if err != nil {
		return service.FilmReadResult{}, err
	}
	result, err := e.filmApplier.Apply(ctx, decision, pep.FilmRow{
		Title:         film.Title,
		TimeElapsedCT: film.TimeElapsedCT,
	})
	if err != nil {
		return service.FilmReadResult{}, err
	}
	return service.FilmReadResult{
		TimeElapsed:     result.Payload["time_elapsed"],
		FieldsDecrypted: result.Decrypted,
		FieldsMasked:    result.Masked,
		FieldsDenied:    result.Denied,
	}, nil
}

func (e *DcsEnforcer) evaluate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	action string,
	resourceID string,
) (types.Decision, error) {
	pi, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       action,
		ResourceType: "film",
		ResourceID:   resourceID,
		Request:      toDCSRequestContext(reqCtx),
		CryptoMeta: map[string]map[string]string{
			"time_elapsed": {"ciphertext_field": "time_elapsed_ct"},
		},
	})
	if err != nil {
		return types.Decision{}, err
	}

	stop := perf.Span(ctx, "pdp_ms")
	decision, _ := e.pdp.Evaluate(pi)
	stop()
	return decision, nil
}

func toDCSPrincipal(p service.Principal) types.Principal {
	return types.Principal{
		TenantID: p.TenantID,
		UserID:   p.UserID,
		Username: p.Username,
		Role:     p.Role,
		Scopes:   p.Scopes,
	}
}

func toDCSRequestContext(c service.RequestContext) types.RequestContext {
	return types.RequestContext{
		RequestID:   c.RequestID,
		ClientIP:    c.ClientIP,
		Channel:     c.Channel,
		Purpose:     c.Purpose,
		DeviceTrust: c.DeviceTrust,
		Env:         c.Env,
	}
}
