package service

import "context"

func EnsureAccessContext(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	action Action,
) context.Context {
	if _, ok := AccessContextFromContext(ctx); ok {
		return ctx
	}
	return WithAccessContext(ctx, AccessContext{
		Principal: principal,
		Request:   reqCtx,
		Action:    action,
	})
}
