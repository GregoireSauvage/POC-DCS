package http

import (
	"context"
	nethttp "net/http"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	transportcore "github.com/neoweyss/poc-dcs/backend-go/internal/transport"
)

func withAccessContext(ctx context.Context, access service.AccessContext) context.Context {
	return service.WithAccessContext(ctx, access)
}

func accessContextFromContext(ctx context.Context) (service.AccessContext, bool) {
	return service.AccessContextFromContext(ctx)
}

func accessContextFromRequest(r *nethttp.Request) (service.AccessContext, bool) {
	return accessContextFromContext(r.Context())
}

func buildAccessContext(r *nethttp.Request, env string) service.AccessContext {
	return service.AccessContext{
		Principal: buildPrincipal(r),
		Request:   buildRequestContext(r, env),
		Action:    transportcore.ResolveHTTPAction(r.Method, r.URL.Path),
	}
}
