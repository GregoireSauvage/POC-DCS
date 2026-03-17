package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type BindingRepository struct {
	pool *Pool
}

func NewBindingRepository(pool *Pool) *BindingRepository {
	return &BindingRepository{pool: pool}
}

func (r *BindingRepository) Get(ctx context.Context, tenantID, resourceType, resourceID string) (service.ResourceBinding, error) {
	var resourceUUID pgtype.UUID
	if err := resourceUUID.Set(resourceID); err != nil {
		return service.ResourceBinding{}, fmt.Errorf("invalid resource id: %w", err)
	}

	query := `
		SELECT tenant_id, resource_type, resource_id, label_payload,
		       profile_id, key_id, payload_hash, label_hash, proof, proof_algorithm,
		       created_at, updated_at
		FROM resource_bindings
		WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
	`

	row := r.pool.QueryRow(ctx, query, tenantID, resourceType, resourceUUID)
	binding, err := scanBindingRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.ResourceBinding{}, service.ErrBindingMissing
		}
		return service.ResourceBinding{}, err
	}
	return binding, nil
}

func (r *BindingRepository) GetMany(ctx context.Context, tenantID, resourceType string, resourceIDs []string) (map[string]service.ResourceBinding, error) {
	results := make(map[string]service.ResourceBinding, len(resourceIDs))
	if len(resourceIDs) == 0 {
		return results, nil
	}

	args := []any{tenantID, resourceType}
	placeholders := make([]string, 0, len(resourceIDs))
	for i, resourceID := range resourceIDs {
		var resourceUUID pgtype.UUID
		if err := resourceUUID.Set(resourceID); err != nil {
			return nil, fmt.Errorf("invalid resource id %s: %w", resourceID, err)
		}
		args = append(args, resourceUUID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+3))
	}

	query := fmt.Sprintf(`
		SELECT tenant_id, resource_type, resource_id, label_payload,
		       profile_id, key_id, payload_hash, label_hash, proof, proof_algorithm,
		       created_at, updated_at
		FROM resource_bindings
		WHERE tenant_id = $1
		  AND resource_type = $2
		  AND resource_id IN (%s)
	`, strings.Join(placeholders, ", "))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query resource bindings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		binding, err := scanBindingRow(rows)
		if err != nil {
			return nil, err
		}
		results[binding.ResourceID] = binding
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resource bindings: %w", err)
	}

	return results, nil
}

func (r *BindingRepository) Upsert(ctx context.Context, binding service.ResourceBinding) error {
	return r.upsertWithExec(ctx, r.pool, binding)
}

func (r *BindingRepository) UpsertInTx(ctx context.Context, tx pgx.Tx, binding service.ResourceBinding) error {
	return r.upsertWithExec(ctx, tx, binding)
}

func (r *BindingRepository) upsertWithExec(ctx context.Context, exec interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
}, binding service.ResourceBinding) error {
	labelPayload, err := json.Marshal(binding.Label)
	if err != nil {
		return fmt.Errorf("marshal binding label: %w", err)
	}

	var resourceUUID pgtype.UUID
	if err := resourceUUID.Set(binding.ResourceID); err != nil {
		return fmt.Errorf("invalid resource id: %w", err)
	}

	query := `
		INSERT INTO resource_bindings (
			tenant_id, resource_type, resource_id, label_payload,
			profile_id, key_id, payload_hash, label_hash, proof, proof_algorithm,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8, $9, $10,
			$11, $12
		)
		ON CONFLICT (tenant_id, resource_type, resource_id)
		DO UPDATE SET
			label_payload = EXCLUDED.label_payload,
			profile_id = EXCLUDED.profile_id,
			key_id = EXCLUDED.key_id,
			payload_hash = EXCLUDED.payload_hash,
			label_hash = EXCLUDED.label_hash,
			proof = EXCLUDED.proof,
			proof_algorithm = EXCLUDED.proof_algorithm,
			updated_at = EXCLUDED.updated_at
	`

	createdAt := binding.Binding.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	updatedAt := binding.Binding.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}

	if _, err := exec.Exec(ctx, query,
		binding.TenantID,
		binding.ResourceType,
		resourceUUID,
		labelPayload,
		binding.Binding.ProfileID,
		binding.Binding.KeyID,
		binding.Binding.PayloadHash,
		binding.Binding.LabelHash,
		binding.Binding.Proof,
		binding.Binding.ProofAlgorithm,
		createdAt,
		updatedAt,
	); err != nil {
		return fmt.Errorf("upsert resource binding: %w", err)
	}

	return nil
}

func scanBindingRow(scanner interface {
	Scan(...interface{}) error
}) (service.ResourceBinding, error) {
	var binding service.ResourceBinding
	var resourceUUID pgtype.UUID
	var rawLabel []byte

	err := scanner.Scan(
		&binding.TenantID,
		&binding.ResourceType,
		&resourceUUID,
		&rawLabel,
		&binding.Binding.ProfileID,
		&binding.Binding.KeyID,
		&binding.Binding.PayloadHash,
		&binding.Binding.LabelHash,
		&binding.Binding.Proof,
		&binding.Binding.ProofAlgorithm,
		&binding.Binding.CreatedAt,
		&binding.Binding.UpdatedAt,
	)
	if err != nil {
		return service.ResourceBinding{}, err
	}

	if resourceUUID.Status == pgtype.Present {
		if err := resourceUUID.AssignTo(&binding.ResourceID); err != nil {
			return service.ResourceBinding{}, fmt.Errorf("parse binding resource id: %w", err)
		}
	}
	if err := json.Unmarshal(rawLabel, &binding.Label); err != nil {
		return service.ResourceBinding{}, fmt.Errorf("unmarshal binding label: %w", err)
	}

	return binding, nil
}

var _ service.BindingStore = (*BindingRepository)(nil)
