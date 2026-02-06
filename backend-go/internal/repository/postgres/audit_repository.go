package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

// AuditLogRepository implements repository.AuditLogRepository using PostgreSQL
type AuditLogRepository struct {
	pool *Pool
}

// NewAuditLogRepository creates a new PostgreSQL audit log repository
func NewAuditLogRepository(pool *Pool) repository.AuditLogRepository {
	return &AuditLogRepository{pool: pool}
}

// Create inserts a new audit log entry
func (r *AuditLogRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}

	// Convert details map to JSON
	var detailsJSON []byte
	var err error
	if log.Details != nil {
		detailsJSON, err = json.Marshal(log.Details)
		if err != nil {
			return fmt.Errorf("failed to marshal details: %w", err)
		}
	}

	query := `
		INSERT INTO audit_logs (
			timestamp, request_id, tenant_id,
			subject_user_id, subject_role,
			action, resource_type, resource_id,
			outcome, decision_hash,
			fields_decrypted, fields_masked, fields_denied,
			details
		) VALUES (
			$1, $2, $3,
			$4, $5,
			$6, $7, $8,
			$9, $10,
			$11, $12, $13,
			$14
		)
		RETURNING id
	`

	err = r.pool.QueryRow(ctx, query,
		log.Timestamp,
		log.RequestID,
		log.TenantID,
		log.SubjectUserID,
		log.SubjectRole,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.Outcome,
		log.DecisionHash,
		log.FieldsDecrypted,
		log.FieldsMasked,
		log.FieldsDenied,
		detailsJSON,
	).Scan(&log.ID)

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// List returns audit logs for a tenant (most recent first)
func (r *AuditLogRepository) List(ctx context.Context, tenantID string, limit int) ([]*domain.AuditLog, error) {
	if limit <= 0 {
		limit = 200
	}

	query := `
		SELECT
			id, timestamp, request_id, tenant_id,
			subject_user_id, subject_role,
			action, resource_type, resource_id,
			outcome, decision_hash,
			fields_decrypted, fields_masked, fields_denied,
			details
		FROM audit_logs
		WHERE tenant_id = $1
		ORDER BY timestamp DESC
		LIMIT $2
	`

	rows, err := r.pool.Query(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		log, err := scanAuditLog(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return logs, nil
}

// scanAuditLog scans an audit log from pgx.Rows
func scanAuditLog(rows pgx.Rows) (*domain.AuditLog, error) {
	var log domain.AuditLog
	var detailsJSON []byte

	err := rows.Scan(
		&log.ID,
		&log.Timestamp,
		&log.RequestID,
		&log.TenantID,
		&log.SubjectUserID,
		&log.SubjectRole,
		&log.Action,
		&log.ResourceType,
		&log.ResourceID,
		&log.Outcome,
		&log.DecisionHash,
		&log.FieldsDecrypted,
		&log.FieldsMasked,
		&log.FieldsDenied,
		&detailsJSON,
	)

	if err != nil {
		return nil, err
	}

	// Unmarshal details JSON
	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &log.Details); err != nil {
			return nil, fmt.Errorf("failed to unmarshal details: %w", err)
		}
	}

	return &log, nil
}
