package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	legacytypes "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
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
	authorizer       service.Authorizer
	filmApplier      *pep.FilmApplier
	spectatorApplier *pep.SpectatorApplier
	kms              CryptoService
	pepperPath       string
}

func New(pipProvider *pip.Provider, authorizer service.Authorizer, filmApplier *pep.FilmApplier, spectatorApplier *pep.SpectatorApplier, kms CryptoService, pepperPath string) *DcsEnforcer {
	return &DcsEnforcer{
		pip:              pipProvider,
		authorizer:       authorizer,
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
	decision, err := e.evaluate(ctx, principal, reqCtx, string(service.ActionFilmCreate), "")
	if err != nil {
		return service.AuthorizationDecision{}, err
	}
	return service.AuthorizationDecision{
		Allow:         decision.Allow,
		Reason:        decision.Reason,
		DecisionHash:  decision.Hash,
		PolicyID:      decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
	}, nil
}

func (e *DcsEnforcer) EvaluateFilmUpdateTime(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	filmID string,
) (service.AuthorizationDecision, error) {
	decision, err := e.evaluate(ctx, principal, reqCtx, string(service.ActionFilmUpdateTime), filmID)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}
	return service.AuthorizationDecision{
		Allow:         decision.Allow,
		Reason:        decision.Reason,
		DecisionHash:  decision.Hash,
		PolicyID:      decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
	}, nil
}

func (e *DcsEnforcer) EvaluateAuditRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
) (service.AuthorizationDecision, error) {
	pi, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       string(service.ActionAuditRead),
		ResourceType: "audit",
		ResourceID:   "audit",
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	decision, err := e.authorizePolicyInput(ctx, pi)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	slog.Debug("audit.read decision",
		slog.String("role", principal.Role),
		slog.String("tenant_id", principal.TenantID),
		slog.Bool("allow", decision.Allow),
		slog.String("reason", decision.Reason),
	)
	return service.AuthorizationDecision{
		Allow:         decision.Allow,
		Reason:        decision.Reason,
		DecisionHash:  decision.Hash,
		PolicyID:      decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
	}, nil
}

func (e *DcsEnforcer) EvaluatePerfRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
) (service.AuthorizationDecision, error) {
	pi, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       string(service.ActionPerfRead),
		ResourceType: "perf",
		ResourceID:   "perf",
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return service.AuthorizationDecision{}, err
	}

	decision, err := e.authorizePolicyInput(ctx, pi)
	if err != nil {
		return service.AuthorizationDecision{}, err
	}
	return service.AuthorizationDecision{
		Allow:         decision.Allow,
		Reason:        decision.Reason,
		DecisionHash:  decision.Hash,
		PolicyID:      decision.PolicyID,
		PolicyVersion: decision.PolicyVersion,
	}, nil
}

func (e *DcsEnforcer) EnforceFilmRead(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	film filmReadInput,
) (filmReadResult, error) {
	decision, err := e.evaluate(ctx, principal, reqCtx, string(service.ActionFilmRead), film.FilmID)
	if err != nil {
		return filmReadResult{}, err
	}
	result, err := e.filmApplier.Apply(ctx, toDCSDecision(decision), pep.FilmRow{
		Title:         film.Title,
		TimeElapsedCT: film.TimeElapsedCT,
	})
	if err != nil {
		return filmReadResult{}, err
	}
	return filmReadResult{
		TimeElapsed:     result.Payload["time_elapsed"],
		FieldsDecrypted: result.Decrypted,
		FieldsMasked:    result.Masked,
		FieldsDenied:    result.Denied,
		DecisionHash:    decision.Hash,
		PolicyID:        decision.PolicyID,
		PolicyVersion:   decision.PolicyVersion,
	}, nil
}

// EnforceFilmCreate authorizes AND encrypts sensitive fields for film creation
// Combines PDP (authorization) + PEP (encryption) in a single operation
// Returns encrypted data ready for database persistence
func (e *DcsEnforcer) EnforceFilmCreate(
	ctx context.Context,
	principal service.Principal,
	reqCtx service.RequestContext,
	input filmCreatePlain,
) (filmCreateEncrypted, error) {
	pi, err := e.pip.Build(ctx, pip.Input{
		Principal:    toDCSPrincipal(principal),
		Action:       string(service.ActionFilmCreate),
		ResourceType: "film",
		Request:      toDCSRequestContext(reqCtx),
	})
	if err != nil {
		return filmCreateEncrypted{}, fmt.Errorf("pip build failed: %w", err)
	}

	decision, err := e.authorizePolicyInput(ctx, pi)
	if err != nil {
		return filmCreateEncrypted{}, err
	}
	if !decision.Allow {
		return filmCreateEncrypted{}, &service.ForbiddenError{
			DecisionHash:  decision.Hash,
			Reason:        decision.Reason,
			PolicyID:      decision.PolicyID,
			PolicyVersion: decision.PolicyVersion,
		}
	}

	stop := perf.Span(ctx, "kms_ms")
	timeElapsedCT, err := e.kms.Encrypt(ctx, strconv.Itoa(input.TimeElapsed))
	stop()
	if err != nil {
		return filmCreateEncrypted{}, fmt.Errorf("encrypt time_elapsed: %w", err)
	}

	return filmCreateEncrypted{
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
) (service.Decision, error) {
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
		return service.Decision{}, err
	}
	return e.authorizePolicyInput(ctx, pi)
}

func (e *DcsEnforcer) authorizePolicyInput(ctx context.Context, policyInput legacytypes.PolicyInput) (service.Decision, error) {
	stop := perf.Span(ctx, "pdp_ms")
	decision, err := e.authorizer.Authorize(ctx, toServicePolicyInput(policyInput))
	stop()
	if err != nil {
		return service.Decision{}, err
	}
	return decision, nil
}

func toDCSPrincipal(p service.Principal) legacytypes.Principal {
	return legacytypes.Principal{
		TenantID: p.TenantID,
		UserID:   p.UserID,
		Username: p.Username,
		Role:     p.Role,
		Scopes:   p.Scopes,
	}
}

func toDCSRequestContext(c service.RequestContext) legacytypes.RequestContext {
	return legacytypes.RequestContext{
		RequestID:   c.RequestID,
		ClientIP:    c.ClientIP,
		Channel:     c.Channel,
		Purpose:     c.Purpose,
		DeviceTrust: c.DeviceTrust,
		Env:         c.Env,
	}
}
