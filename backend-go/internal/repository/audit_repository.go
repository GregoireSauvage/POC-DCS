package repository

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// AuditLogRepository defines audit log persistence operations
type AuditLogRepository interface {
	// Create inserts a new audit log entry
	Create(ctx context.Context, log *domain.AuditLog) error

	// List returns audit logs with optional filters
	List(ctx context.Context, tenantID string, limit int) ([]*domain.AuditLog, error)
}
