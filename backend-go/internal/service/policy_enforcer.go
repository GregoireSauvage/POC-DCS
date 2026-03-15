package service

import "context"

type FilmReadInput struct {
	FilmID        string
	Title         string
	TimeElapsedCT string
}

type FilmCreateInput struct {
	Title       string
	TimeElapsed int
}

// FilmCreatePlain represents plaintext film data before encryption
// Used as input to DCS enforcer for authorization + encryption
type FilmCreatePlain struct {
	Title       string
	TimeElapsed int
}

// FilmCreateEncrypted represents film data after encryption by DCS enforcer
// Ready for database persistence
type FilmCreateEncrypted struct {
	Title         string // Public field (not encrypted)
	TimeElapsedCT string // Encrypted ciphertext from KMS
}

type FilmReadResult struct {
	TimeElapsed     interface{}
	FieldsDecrypted []string // Fields that were decrypted for audit logging
	FieldsMasked    []string // Fields that were masked for audit logging
	FieldsDenied    []string // Fields that were denied for audit logging
}

type AuthorizationDecision struct {
	Allow        bool
	Reason       string
	DecisionHash string // Hash of PDP decision for audit correlation
}

type PolicyEnforcer interface {
	// Generic crypto operations (delegated to KMS)
	Encrypt(ctx context.Context, plaintext string) (string, error)
	Decrypt(ctx context.Context, ciphertext string) (string, error)
	GetPepper(ctx context.Context, path string) ([]byte, error)

	EvaluateAuditRead(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
	) (AuthorizationDecision, error)
	EvaluatePerfRead(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
	) (AuthorizationDecision, error)
	EvaluateFilmCreate(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
	) (AuthorizationDecision, error)
	EvaluateFilmUpdateTime(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		filmID string,
	) (AuthorizationDecision, error)
	EnforceFilmRead(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		film FilmReadInput,
	) (FilmReadResult, error)

	// EnforceFilmCreate authorizes AND encrypts sensitive fields for film creation
	// This combines PDP (authorization) + PEP (encryption) in a single call
	// Returns encrypted data ready for database persistence
	EnforceFilmCreate(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		input FilmCreatePlain,
	) (FilmCreateEncrypted, error)

	// Hall policies
	EvaluateHallCreate(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		ownerUserID string,
	) (AuthorizationDecision, error)
	EvaluateHallRead(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		hallID string,
		ownerUserID string,
	) (AuthorizationDecision, error)
	EnforceHallRead(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		hall HallReadInput,
	) (HallReadResult, error)

	// Spectator policies
	EvaluateSpectatorCreate(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		ownerUserID string,
	) (AuthorizationDecision, error)
	EvaluateSpectatorSearch(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
	) (AuthorizationDecision, error)
	EnforceSpectatorRead(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		spectator SpectatorReadInput,
	) (SpectatorReadResult, error)

	// EnforceSpectatorCreate authorizes, encrypts PII fields AND computes HMAC lookup
	// This combines PDP (authorization) + PEP (encryption + HMAC) in a single call
	// Returns encrypted data ready for database persistence with searchable encryption
	EnforceSpectatorCreate(
		ctx context.Context,
		principal Principal,
		reqCtx RequestContext,
		input SpectatorCreatePlain,
	) (SpectatorCreateEncrypted, error)
}
