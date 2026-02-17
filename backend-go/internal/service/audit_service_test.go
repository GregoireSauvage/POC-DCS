package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

// Mock AuditLogRepository
type mockAuditRepository struct {
	logs      []*domain.AuditLog
	createErr error
	listErr   error
}

func (m *mockAuditRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.logs = append(m.logs, log)
	return nil
}

func (m *mockAuditRepository) List(ctx context.Context, tenantID string, limit int) ([]*domain.AuditLog, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var result []*domain.AuditLog
	for _, log := range m.logs {
		if log.TenantID == tenantID {
			result = append(result, log)
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func TestAuditService_List_RepositoryError(t *testing.T) {
	mockRepo := &mockAuditRepository{
		logs:    []*domain.AuditLog{},
		listErr: repository.ErrInvalidInput,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditSvc := NewAuditService(mockRepo, nil, logger)

	_, err := auditSvc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{}, 10)
	if !errors.Is(err, repository.ErrInvalidInput) {
		t.Fatalf("expected repository error, got %v", err)
	}
}

func TestAuditService_WriteAudit(t *testing.T) {
	mockRepo := &mockAuditRepository{logs: make([]*domain.AuditLog, 0)}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditSvc := NewAuditService(mockRepo, nil, logger)

	log := &domain.AuditLog{
		RequestID:       "req-123",
		TenantID:        "t1",
		SubjectUserID:   "user-1",
		SubjectRole:     "developer",
		Action:          "film.read",
		ResourceType:    "film",
		ResourceID:      "film-1",
		Outcome:         "allow",
		DecisionHash:    "hash-abc",
		FieldsDecrypted: []string{"title"},
		FieldsMasked:    []string{"time_elapsed"},
		FieldsDenied:    []string{},
	}

	err := auditSvc.WriteAudit(context.Background(), log)
	if err != nil {
		t.Fatalf("WriteAudit failed: %v", err)
	}

	if len(mockRepo.logs) != 1 {
		t.Errorf("Expected 1 audit log, got %d", len(mockRepo.logs))
	}

	savedLog := mockRepo.logs[0]
	if savedLog.RequestID != "req-123" {
		t.Errorf("Expected RequestID req-123, got %s", savedLog.RequestID)
	}
	if savedLog.Action != "film.read" {
		t.Errorf("Expected Action film.read, got %s", savedLog.Action)
	}
}

func TestAuditService_WriteAudit_NoRepository(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditSvc := NewAuditService(nil, nil, logger)

	log := &domain.AuditLog{
		RequestID: "req-123",
		TenantID:  "t1",
	}

	// Should not error when repo is nil
	err := auditSvc.WriteAudit(context.Background(), log)
	if err != nil {
		t.Errorf("WriteAudit with nil repo should not error, got: %v", err)
	}
}

func TestAuditService_WriteAudit_RepositoryError(t *testing.T) {
	mockRepo := &mockAuditRepository{
		logs:      make([]*domain.AuditLog, 0),
		createErr: repository.ErrInvalidInput,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditSvc := NewAuditService(mockRepo, nil, logger)

	log := &domain.AuditLog{
		RequestID: "req-123",
		TenantID:  "t1",
	}

	err := auditSvc.WriteAudit(context.Background(), log)
	if err == nil {
		t.Error("Expected WriteAudit to return error from repository")
	}
}

func TestAuditService_List(t *testing.T) {
	mockRepo := &mockAuditRepository{
		logs: []*domain.AuditLog{
			{ID: 1, TenantID: "t1", Action: "film.read"},
			{ID: 2, TenantID: "t1", Action: "film.update"},
			{ID: 3, TenantID: "t2", Action: "film.read"},
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditSvc := NewAuditService(mockRepo, nil, logger)

	logs, err := auditSvc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{}, 10)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(logs) != 2 {
		t.Errorf("Expected 2 logs for t1, got %d", len(logs))
	}

	for _, log := range logs {
		if log.TenantID != "t1" {
			t.Errorf("Expected all logs to have TenantID t1, got %s", log.TenantID)
		}
	}
}

func TestAuditService_List_NoRepository(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	auditSvc := NewAuditService(nil, nil, logger)

	logs, err := auditSvc.List(context.Background(), Principal{TenantID: "t1"}, RequestContext{}, 10)
	if err != nil {
		t.Fatalf("List with nil repo should not error, got: %v", err)
	}

	if logs == nil {
		t.Error("Expected empty slice when repo is nil")
	}
}
