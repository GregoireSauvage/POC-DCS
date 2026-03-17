package http

import (
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	transportcore "github.com/neoweyss/poc-dcs/backend-go/internal/transport"
)

func resolveHTTPAction(method, path string) service.Action {
	return transportcore.ResolveHTTPAction(method, path)
}
