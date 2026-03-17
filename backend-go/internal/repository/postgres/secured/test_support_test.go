package secured

import (
	"context"
	"io"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func withAccess(role string, action service.Action) context.Context {
	return service.WithAccessContext(context.Background(), service.AccessContext{
		Principal: service.Principal{TenantID: "t1", UserID: "u-1", Username: role, Role: role},
		Request:   service.RequestContext{RequestID: "req-1", Channel: "web", Purpose: "access", Env: "test"},
		Action:    action,
	})
}
