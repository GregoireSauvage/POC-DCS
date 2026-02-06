package domain

import "time"

// User represents a user in the system
type User struct {
	ID           string                 `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	Username     string                 `json:"username"`
	PasswordHash string                 `json:"-"` // Never expose password hash
	Role         string                 `json:"role"`
	Labels       map[string]interface{} `json:"labels,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}
