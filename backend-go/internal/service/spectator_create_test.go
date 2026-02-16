package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

// ============================================================================
// Test Mocks for Spectator
// ============================================================================

type fakeSpectatorRepo struct {
	createErr             error
	createdSpectators     []*domain.Spectator
	findByLookupResult    []*domain.Spectator
	findByLookupErr       error
	findByLookupCallCount int
}

func (f *fakeSpectatorRepo) Create(ctx context.Context, spectator *domain.Spectator) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.createdSpectators = append(f.createdSpectators, spectator)
	return nil
}

func (f *fakeSpectatorRepo) FindByExternalIDLookup(ctx context.Context, tenantID string, lookup []byte) ([]*domain.Spectator, error) {
	f.findByLookupCallCount++
	if f.findByLookupErr != nil {
		return nil, f.findByLookupErr
	}
	// Filter by tenant
	var result []*domain.Spectator
	for _, sp := range f.findByLookupResult {
		if sp.TenantID == tenantID {
			result = append(result, sp)
		}
	}
	return result, nil
}

func (f *fakeSpectatorRepo) CountByHall(ctx context.Context, tenantID, hallID string) (int, error) {
	return 0, nil
}

type fakeHallRepoForSpectator struct {
	halls       map[string]*domain.Hall // key: tenantID:hallID
	findByIDErr error
}

func (f *fakeHallRepoForSpectator) FindByID(ctx context.Context, tenantID string, hallID string) (*domain.Hall, error) {
	if f.findByIDErr != nil {
		return nil, f.findByIDErr
	}
	key := tenantID + ":" + hallID
	return f.halls[key], nil
}

func (f *fakeHallRepoForSpectator) ListByTenant(ctx context.Context, tenantID string) ([]HallRecord, error) {
	return nil, nil
}

func (f *fakeHallRepoForSpectator) Create(ctx context.Context, hall *domain.Hall) error {
	return nil
}

func (f *fakeHallRepoForSpectator) CountSpectators(ctx context.Context, tenantID, hallID string) (int, error) {
	return 0, nil
}

type fakeKMSWithPepper struct {
	*fakeKMS
	pepper      []byte
	pepperErr   error
	pepperCalls int
}

func (f *fakeKMSWithPepper) GetPepper(ctx context.Context, path string) ([]byte, error) {
	f.pepperCalls++
	if f.pepperErr != nil {
		return nil, f.pepperErr
	}
	if f.pepper == nil {
		return []byte("default-pepper-secret"), nil
	}
	return f.pepper, nil
}

// ============================================================================
// POST /spectators - Create Tests
// ============================================================================

func TestSpectatorService_Create_AdminAllowed_AllDecrypted(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{
			"t1:hall-1": {
				TenantID:    "t1",
				ID:          "hall-1",
				Name:        "IMAX",
				OwnerUserID: "owner-123",
			},
		},
	}
	kms := &fakeKMSWithPepper{
		fakeKMS: &fakeKMS{
			encryptValue: "vault:v1:encrypted",
		},
		pepper: []byte("test-pepper"),
	}
	enforcer := &fakePolicyEnforcer{
		evaluateSpectatorCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{
				Allow:        true,
				Reason:       "admin_allowed",
				DecisionHash: "hash-create",
			}, nil
		},
		enforceSpectatorReadFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input SpectatorReadInput) (SpectatorReadResult, error) {
			// Admin sees all decrypted
			return SpectatorReadResult{
				Name:            "John Doe",
				Age:             25,
				ExternalID:      "ABC123",
				FieldsDecrypted: []string{"name", "age", "external_id"},
				FieldsMasked:    []string{},
				FieldsDenied:    []string{},
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "admin-user",
		Username: "admin",
		Role:     "admin",
	}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	spectator, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "hall-1",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, spectator.ID)
	assert.Equal(t, "hall-1", spectator.HallID)
	assert.Equal(t, "John Doe", spectator.Name)
	assert.Equal(t, 25, spectator.Age)
	assert.Equal(t, "ABC123", spectator.ExternalID)

	// Verify spectator was created in repo
	require.Len(t, spectatorRepo.createdSpectators, 1)
	created := spectatorRepo.createdSpectators[0]
	assert.Equal(t, "t1", created.TenantID)
	assert.Equal(t, "hall-1", created.HallID)
	assert.Equal(t, "vault:v1:encrypted", created.NameCT)
	assert.Equal(t, "vault:v1:encrypted", created.AgeCT)
	assert.Equal(t, "vault:v1:encrypted", created.ExternalIDCT)
	assert.NotEmpty(t, created.ExternalIDLookup, "HMAC lookup should be computed")

	// Verify audit log
	require.Len(t, auditSvc.allAuditLogs, 1)
	assert.Equal(t, "spectator.create", auditSvc.allAuditLogs[0].Action)
	assert.Equal(t, "allow", auditSvc.allAuditLogs[0].Outcome)
	assert.Equal(t, "hash-create", auditSvc.allAuditLogs[0].DecisionHash)
}

func TestSpectatorService_Create_AgentAllowed_PIIMasked(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{
			"t1:hall-1": {
				TenantID:    "t1",
				ID:          "hall-1",
				OwnerUserID: "owner-123",
			},
		},
	}
	kms := &fakeKMSWithPepper{
		fakeKMS:  &fakeKMS{encryptValue: "vault:v1:encrypted"},
		pepper:   []byte("test-pepper"),
	}
	enforcer := &fakePolicyEnforcer{
		evaluateSpectatorCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{
				Allow:        true,
				Reason:       "agent_allowed",
				DecisionHash: "hash-agent",
			}, nil
		},
		enforceSpectatorReadFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input SpectatorReadInput) (SpectatorReadResult, error) {
			// Agent sees age decrypted, PII (name, external_id) masked
			return SpectatorReadResult{
				Name:            "J***",       // Masked
				Age:             25,           // Decrypted
				ExternalID:      "A***",       // Masked
				FieldsDecrypted: []string{"age"},
				FieldsMasked:    []string{"name", "external_id"},
				FieldsDenied:    []string{},
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "agent-user",
		Username: "agent",
		Role:     "agent",
	}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	spectator, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "hall-1",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "J***", spectator.Name, "Agent should see masked name")
	assert.Equal(t, 25, spectator.Age, "Agent should see decrypted age")
	assert.Equal(t, "A***", spectator.ExternalID, "Agent should see masked external_id")

	// Verify spectator ID is masked for non-admin
	spectatorIDStr, ok := spectator.ID.(string)
	require.True(t, ok, "Spectator ID should be masked string for agent")
	assert.Contains(t, spectatorIDStr, "…", "Should be UUID masked format")
}

func TestSpectatorService_Create_DeveloperDenied(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{
			"t1:hall-1": {TenantID: "t1", ID: "hall-1", OwnerUserID: "owner-123"},
		},
	}
	kms := &fakeKMSWithPepper{
		fakeKMS: &fakeKMS{encryptValue: "vault:v1:encrypted"},
		pepper:  []byte("test-pepper"),
	}
	enforcer := &fakePolicyEnforcer{
		evaluateSpectatorCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error) {
			// Developer is denied for write actions
			return AuthorizationDecision{
				Allow:        false,
				Reason:       "write_forbidden",
				DecisionHash: "hash-deny",
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "dev-user",
		Username: "developer",
		Role:     "developer",
	}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "hall-1",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.Error(t, err)
	assert.Equal(t, ErrForbidden, err)

	// Verify no spectator was created
	assert.Empty(t, spectatorRepo.createdSpectators)

	// Verify audit log shows deny
	require.Len(t, auditSvc.allAuditLogs, 1)
	assert.Equal(t, "spectator.create", auditSvc.allAuditLogs[0].Action)
	assert.Equal(t, "deny", auditSvc.allAuditLogs[0].Outcome)

	// Verify perf log was written even on deny (Python parity)
	assert.Equal(t, 1, perfWriter.calls, "Perf should be logged even on deny")
}

func TestSpectatorService_Create_HallNotFound_ReturnsNotFound(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{}, // Empty - no halls
	}
	kms := &fakeKMSWithPepper{
		fakeKMS: &fakeKMS{encryptValue: "vault:v1:encrypted"},
		pepper:  []byte("test-pepper"),
	}
	enforcer := &fakePolicyEnforcer{}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "nonexistent-hall",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.Error(t, err)
	assert.Equal(t, ErrNotFound, err)
	assert.Empty(t, spectatorRepo.createdSpectators, "Should not create spectator when hall not found")
}

func TestSpectatorService_Create_PolicyEvaluationError_ReturnsError(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{
			"t1:hall-1": {TenantID: "t1", ID: "hall-1", OwnerUserID: "owner-123"},
		},
	}
	kms := &fakeKMSWithPepper{
		fakeKMS: &fakeKMS{encryptValue: "vault:v1:encrypted"},
		pepper:  []byte("test-pepper"),
	}
	policyErr := errors.New("policy engine unavailable")
	enforcer := &fakePolicyEnforcer{
		evaluateSpectatorCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{}, policyErr
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "hall-1",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.Error(t, err)
	assert.Equal(t, policyErr, err)
	assert.Empty(t, spectatorRepo.createdSpectators)
}

func TestSpectatorService_Create_EncryptionError_ReturnsError(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{
			"t1:hall-1": {TenantID: "t1", ID: "hall-1", OwnerUserID: "owner-123"},
		},
	}
	encryptErr := errors.New("vault unavailable")
	kms := &fakeKMSWithPepper{
		fakeKMS: &fakeKMS{
			encryptErr: encryptErr,
		},
		pepper: []byte("test-pepper"),
	}
	enforcer := &fakePolicyEnforcer{
		evaluateSpectatorCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "hall-1",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt")
	assert.Empty(t, spectatorRepo.createdSpectators)
}

func TestSpectatorService_Create_RepositoryError_ReturnsError(t *testing.T) {
	// Arrange
	dbErr := errors.New("database connection lost")
	spectatorRepo := &fakeSpectatorRepo{
		createErr: dbErr,
	}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{
			"t1:hall-1": {TenantID: "t1", ID: "hall-1", OwnerUserID: "owner-123"},
		},
	}
	kms := &fakeKMSWithPepper{
		fakeKMS: &fakeKMS{encryptValue: "vault:v1:encrypted"},
		pepper:  []byte("test-pepper"),
	}
	enforcer := &fakePolicyEnforcer{
		evaluateSpectatorCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	_, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "hall-1",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.Error(t, err)
	assert.Equal(t, dbErr, err)
}

func TestSpectatorService_Create_DCSOff_IDNotMasked(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{
		halls: map[string]*domain.Hall{
			"t1:hall-1": {TenantID: "t1", ID: "hall-1", OwnerUserID: "owner-123"},
		},
	}
	kms := &fakeKMSWithPepper{
		fakeKMS: &fakeKMS{encryptValue: "vault:v1:encrypted"},
		pepper:  []byte("test-pepper"),
	}
	enforcer := &fakePolicyEnforcer{
		evaluateSpectatorCreateFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (AuthorizationDecision, error) {
			return AuthorizationDecision{Allow: true, DecisionHash: "hash"}, nil
		},
		enforceSpectatorReadFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input SpectatorReadInput) (SpectatorReadResult, error) {
			return SpectatorReadResult{
				Name:            "John Doe",
				Age:             25,
				ExternalID:      "ABC123",
				FieldsDecrypted: []string{"name", "age", "external_id"},
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{
		dcsEnabled: false, // DCS disabled
		cacheLevel: 0,
	}

	svc := NewSpectatorService(spectatorRepo, hallRepo, kms, enforcer, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "dev-user",
		Role:     "developer", // Non-admin
	}
	reqCtx := RequestContext{RequestID: "req-123"}

	// Act
	spectator, _, err := svc.Create(context.Background(), principal, reqCtx, SpectatorCreateInput{
		HallID:     "hall-1",
		Name:       "John Doe",
		Age:        25,
		ExternalID: "ABC123",
	})

	// Assert
	require.NoError(t, err)
	// When DCS is off, ID should NOT be masked even for non-admin (Python parity)
	spectatorIDStr, ok := spectator.ID.(string)
	require.True(t, ok, "ID should be a string")
	// Verify it's a full UUID, not masked (no ellipsis character)
	assert.NotContains(t, spectatorIDStr, "…", "ID should be full UUID when DCS is off, not masked")
}
