package repository

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// UserRepository defines user persistence operations
type UserRepository interface {
	// GetByUsername returns a user by tenant and username
	GetByUsername(ctx context.Context, tenantID, username string) (*domain.User, error)
}
