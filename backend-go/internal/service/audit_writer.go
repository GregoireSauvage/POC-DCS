package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// AuditWriter defines the interface for writing audit logs.
// This abstraction allows for easier testing and potential future implementations.
type AuditWriter interface {
	WriteAudit(ctx context.Context, log *domain.AuditLog) error
}
