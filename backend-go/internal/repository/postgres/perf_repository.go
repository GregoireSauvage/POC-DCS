package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

// PerfLogRepository implements repository.PerfLogRepository using PostgreSQL.
type PerfLogRepository struct {
	pool *Pool
}

// NewPerfLogRepository creates a new PostgreSQL perf log repository.
func NewPerfLogRepository(pool *Pool) repository.PerfLogRepository {
	return &PerfLogRepository{pool: pool}
}

// Create inserts a new perf log entry.
func (r *PerfLogRepository) Create(ctx context.Context, log *domain.PerfLog) error {
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now().UTC()
	}

	subjectUserID := nullableUUID(log.SubjectUserID)
	subjectRole := nullableString(log.SubjectRole)

	query := `
		INSERT INTO perf_logs (
			ts, request_id,
			tenant_id, subject_user_id, subject_role,
			action, resource_type,
			dcs_enabled, cache_level,
			total_ms, pip_ms, pdp_ms, kms_ms, db_ms
		) VALUES (
			$1, $2,
			$3, $4, $5,
			$6, $7,
			$8, $9,
			$10, $11, $12, $13, $14
		)
	`

	_, err := r.pool.Exec(ctx, query,
		log.Timestamp,
		log.RequestID,
		log.TenantID,
		subjectUserID,
		subjectRole,
		log.Action,
		log.ResourceType,
		log.DCSEnabled,
		log.CacheLevel,
		log.TotalMS,
		log.PIPMS,
		log.PDPMS,
		log.KMSMS,
		log.DBMS,
	)
	if err != nil {
		return fmt.Errorf("failed to create perf log: %w", err)
	}
	return nil
}

// List returns perf logs for a tenant with optional action filter.
func (r *PerfLogRepository) List(
	ctx context.Context,
	tenantID string,
	limit int,
	action *string,
) ([]*domain.PerfLog, error) {
	if limit <= 0 {
		limit = 200
	}

	query := `
		SELECT
			ts, request_id, tenant_id,
			subject_user_id, subject_role,
			action, resource_type,
			dcs_enabled, cache_level,
			COALESCE(total_ms, 0),
			pip_ms, pdp_ms, kms_ms, db_ms
		FROM perf_logs
		WHERE tenant_id = $1
	`
	args := []interface{}{tenantID}

	if action != nil {
		query += " AND action = $" + strconv.Itoa(len(args)+1)
		args = append(args, strings.TrimSpace(*action))
	}

	query += " ORDER BY ts DESC LIMIT $" + strconv.Itoa(len(args)+1)
	args = append(args, limit)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query perf logs: %w", err)
	}
	defer rows.Close()

	var logs []*domain.PerfLog
	for rows.Next() {
		log, err := scanPerfLog(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan perf log: %w", err)
		}
		logs = append(logs, log)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating perf logs: %w", err)
	}
	return logs, nil
}

// Summary returns aggregated perf results for a tenant with filters.
func (r *PerfLogRepository) Summary(
	ctx context.Context,
	tenantID string,
	action *string,
	cacheLevel *int,
	allCacheLevels bool,
) ([]*domain.PerfSummary, error) {
	query := `
		SELECT
			action,
			dcs_enabled,
			cache_level,
			AVG(total_ms) AS avg_total_ms,
			COUNT(*) AS count
		FROM perf_logs
		WHERE tenant_id = $1
	`
	args := []interface{}{tenantID}

	if action != nil {
		query += " AND action = $" + strconv.Itoa(len(args)+1)
		args = append(args, strings.TrimSpace(*action))
	}

	if !allCacheLevels && cacheLevel != nil {
		query += " AND cache_level = $" + strconv.Itoa(len(args)+1)
		args = append(args, *cacheLevel)
	}

	query += `
		GROUP BY action, dcs_enabled, cache_level
		ORDER BY action ASC, dcs_enabled DESC, cache_level ASC
	`

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query perf summary: %w", err)
	}
	defer rows.Close()

	var summaries []*domain.PerfSummary
	for rows.Next() {
		row, err := scanPerfSummary(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan perf summary: %w", err)
		}
		summaries = append(summaries, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating perf summary: %w", err)
	}
	return summaries, nil
}

func scanPerfLog(row pgx.Row) (*domain.PerfLog, error) {
	var log domain.PerfLog
	var pipMS *float64
	var pdpMS *float64
	var kmsMS *float64
	var dbMS *float64
	var subjectUserID pgtype.UUID
	var subjectRole *string

	err := row.Scan(
		&log.Timestamp,
		&log.RequestID,
		&log.TenantID,
		&subjectUserID,
		&subjectRole,
		&log.Action,
		&log.ResourceType,
		&log.DCSEnabled,
		&log.CacheLevel,
		&log.TotalMS,
		&pipMS,
		&pdpMS,
		&kmsMS,
		&dbMS,
	)
	if err != nil {
		return nil, err
	}

	if subjectUserID.Status == pgtype.Present {
		var id string
		if err := subjectUserID.AssignTo(&id); err == nil {
			log.SubjectUserID = id
		}
	}
	if subjectRole != nil {
		log.SubjectRole = *subjectRole
	}

	log.PIPMS = pipMS
	log.PDPMS = pdpMS
	log.KMSMS = kmsMS
	log.DBMS = dbMS

	return &log, nil
}

func scanPerfSummary(row pgx.Row) (*domain.PerfSummary, error) {
	var summary domain.PerfSummary
	var avgTotalMS *float64

	err := row.Scan(
		&summary.Action,
		&summary.DCSEnabled,
		&summary.CacheLevel,
		&avgTotalMS,
		&summary.Count,
	)
	if err != nil {
		return nil, err
	}

	summary.AvgTotalMS = avgTotalMS

	return &summary, nil
}

func nullableString(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullableUUID(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var uuid pgtype.UUID
	if err := uuid.Set(value); err != nil {
		return nil
	}
	return uuid
}
