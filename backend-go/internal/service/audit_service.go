package service

import (
	"context"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
)

// AuditService handles audit logging
type AuditService struct {
	repo       repository.AuditLogRepository
	authorizer Authorizer
	logger     *slog.Logger
}

func NewAuditService(
	repo repository.AuditLogRepository,
	authorizer Authorizer,
	logger *slog.Logger,
) *AuditService {
	return &AuditService{
		repo:       repo,
		authorizer: authorizer,
		logger:     logger,
	}
}

// WriteAudit writes an audit log entry
func (s *AuditService) WriteAudit(ctx context.Context, log *domain.AuditLog) error {
	if s == nil {
		return nil
	}
	if s.repo == nil {
		s.logger.Warn("audit repository not configured, skipping audit log")
		return nil
	}

	if log.PolicyID != "" || log.PolicyVersion != "" {
		if log.Details == nil {
			log.Details = map[string]interface{}{}
		}
		if log.PolicyID != "" {
			log.Details["policy_id"] = log.PolicyID
		}
		if log.PolicyVersion != "" {
			log.Details["policy_version"] = log.PolicyVersion
		}
	}

	if err := s.repo.Create(ctx, log); err != nil {
		s.logger.Error("failed to write audit log",
			slog.String("error", err.Error()),
			slog.String("action", log.Action),
			slog.String("resource_type", log.ResourceType),
		)
		return err
	}

	if s.logger != nil {
		s.logger.Debug("audit log written",
			slog.String("request_id", log.RequestID),
			slog.String("action", log.Action),
			slog.String("outcome", log.Outcome),
			slog.Int("fields_decrypted", len(log.FieldsDecrypted)),
			slog.Int("fields_masked", len(log.FieldsMasked)),
			slog.Int("fields_denied", len(log.FieldsDenied)),
		)
	}

	return nil
}

// List returns audit logs for a tenant after DCS evaluation
func (s *AuditService) List(
	ctx context.Context,
	principal Principal,
	reqCtx RequestContext,
	limit int,
) ([]*domain.AuditLog, error) {
	if s.authorizer != nil {
		decision, err := s.authorizer.Authorize(ctx, PolicyInput{
			Access: AccessContext{Principal: principal, Request: reqCtx, Action: ActionAuditRead},
			Resource: Resource{
				Type:     "audit",
				TenantID: principal.TenantID,
				Fields:   map[string]FieldMeta{},
			},
		})
		if err != nil {
			return nil, err
		}
		if !decision.Allow {
			return nil, ErrForbidden
		}
	} else {
		return nil, ErrDCSNotConfigured
	}

	if s.repo == nil {
		return []*domain.AuditLog{}, nil
	}

	return s.repo.List(ctx, principal.TenantID, limit)
}
