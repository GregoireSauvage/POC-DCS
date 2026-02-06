package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v4"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

// UserRepository implements repository.UserRepository using PostgreSQL
type UserRepository struct {
	pool *Pool
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(pool *Pool) repository.UserRepository {
	return &UserRepository{pool: pool}
}

// GetByUsername returns a user by tenant and username
func (r *UserRepository) GetByUsername(ctx context.Context, tenantID, username string) (*domain.User, error) {
	query := `
		SELECT id, tenant_id, username, password_hash, role, labels, created_at
		FROM users
		WHERE tenant_id = $1 AND username = $2
	`

	var user domain.User
	err := r.pool.QueryRow(ctx, query, tenantID, username).Scan(
		&user.ID,
		&user.TenantID,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&user.Labels,
		&user.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}
