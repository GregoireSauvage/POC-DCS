package service

import "context"

type Principal struct {
	TenantID string
	UserID   string
	Username string
	Role     string
	Scopes   []string
}

type RequestContext struct {
	RequestID   string
	ClientIP    string
	Channel     string
	Purpose     string
	DeviceTrust float64
	Env         string
}

type FilmReadInput struct {
	FilmID        string
	Title         string
	TimeElapsedCT string
}

type FilmReadResult struct {
	TimeElapsed interface{}
}

type AuthorizationDecision struct {
	Allow  bool
	Reason string
}

type PolicyEnforcer interface {
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
}
