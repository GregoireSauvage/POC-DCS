package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pdp"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// CryptoService provides encryption, decryption and pepper management
// Used by DCS enforcer for PEP (Policy Enforcement Point) operations
type CryptoService interface {
	Encrypt(ctx context.Context, plaintext string) (string, error)
	Decrypt(ctx context.Context, ciphertext string) (string, error)
	GetPepper(ctx context.Context, path string) ([]byte, error)
}

type DcsEnforcer struct {
	pip              *pip.Provider
	pdp              *pdp.Engine
	filmApplier      *pep.FilmApplier
	spectatorApplier *pep.SpectatorApplier
	kms              CryptoService // Full crypto service (encrypt + decrypt + pepper)
	pepperPath       string        // Vault KV path for HMAC pepper
}

func New(pipProvider *pip.Provider, pdpEngine *pdp.Engine, filmApplier *pep.FilmApplier, spectatorApplier *pep.SpectatorApplier, kms CryptoService, pepperPath string) *DcsEnforcer {
	return &DcsEnforcer{
		pip:              pipProvider,
		pdp:              pdpEngine,
		filmApplier:      filmApplier,
		spectatorApplier: spectatorApplier,
		kms:              kms,
		pepperPath:       pepperPath,
	}
}

// Encrypt delegates to the underlying KMS for direct encryption needs
func (e *DcsEnforcer) Encrypt(ctx context.Context, plaintext string) (string, error) {
	return e.kms.Encrypt(ctx, plaintext)
}

// Decrypt delegates to the underlying KMS for direct decryption needs
func (e *DcsEnforcer) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	return e.kms.Decrypt(ctx, ciphertext)
}

// GetPepper delegates to the underlying KMS for pepper retrieval
func (e *DcsEnforcer) GetPepper(ctx context.Context, path string) ([]byte, error) {
	return e.kms.GetPepper(ctx, path)
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

	slog.Debug("perf.read decision",
		slog.String("role", principal.Role),
		slog.String("tenant_id", principal.TenantID),
		slog.Bool("allow", decision.Allow),
		slog.String("reason", decision.Reason),
	)
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

// EnforceFilmCreate authorizes AND encrypts sensitive fields for film creation
// Combines PDP (authorization) + PEP (encryption) in a single operation
// Returns encrypted data ready for database persistence
func (e *DcsEnforcer) EnforceFilmCreate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	input service.FilmCreatePlain,
) (service.FilmCreateEncrypted, error) {

	// Phase 1: PIP - Build policy input
	pi, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       "film.create",
		ResourceType: "film",
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.FilmCreateEncrypted{}, fmt.Errorf("pip build failed: %w", err)
	}

	// Phase 2: PDP - Evaluate authorization
	stop := perf.Span(ctx, "pdp_ms")
	decision, _ := e.pdp.Evaluate(pi)
	stop()

	if !decision.Allow {
		return service.FilmCreateEncrypted{}, service.ErrForbidden
	}

	// Phase 3: PEP - Encrypt sensitive fields
	stop = perf.Span(ctx, "kms_ms")
	timeElapsedCT, err := e.kms.Encrypt(ctx, strconv.Itoa(input.TimeElapsed))
	stop()
	if err != nil {
		return service.FilmCreateEncrypted{}, fmt.Errorf("encrypt time_elapsed: %w", err)
	}

	return service.FilmCreateEncrypted{
		Title:         input.Title,
		TimeElapsedCT: timeElapsedCT,
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
