package service

import "context"

type accessContextKey struct{}

func WithAccessContext(ctx context.Context, access AccessContext) context.Context {
	return context.WithValue(ctx, accessContextKey{}, access)
}

func AccessContextFromContext(ctx context.Context) (AccessContext, bool) {
	access, ok := ctx.Value(accessContextKey{}).(AccessContext)
	return access, ok
}
