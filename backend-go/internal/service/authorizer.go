package service

import "context"

type Authorizer interface {
	Authorize(ctx context.Context, input PolicyInput) (Decision, error)
}
