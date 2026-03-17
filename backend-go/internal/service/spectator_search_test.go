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
// GET /spectators/search - Search Tests
// ============================================================================

func TestSpectatorService_Search_AdminFindsMultiple_AllDecrypted(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{
		findByLookupResult: []*domain.Spectator{
			{
				TenantID:         "t1",
				ID:               "spectator-1",
				HallID:           "hall-1",
				NameCT:           "vault:v1:encrypted-name1",
				AgeCT:            "vault:v1:encrypted-age1",
				ExternalIDCT:     "vault:v1:encrypted-id1",
				ExternalIDLookup: []byte("hmac-lookup"),
			},
			{
				TenantID:         "t1",
				ID:               "spectator-2",
				HallID:           "hall-2",
				NameCT:           "vault:v1:encrypted-name2",
				AgeCT:            "vault:v1:encrypted-age2",
				ExternalIDCT:     "vault:v1:encrypted-id2",
				ExternalIDLookup: []byte("hmac-lookup"),
			},
		},
	}
	hallRepo := &fakeHallRepoForSpectator{}
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			return Decision{
				Allow:        true,
				Reason:       "admin_allowed",
				Hash: "hash-search",
			}, nil
		},
		shapeReadFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input spectatorRuleInput) (spectatorRuleResult, error) {
			// Admin sees all decrypted
			name := "John Doe"
			if input.SpectatorID == "spectator-2" {
				name = "Jane Smith"
			}
			return spectatorRuleResult{
				Name:            name,
				Age:             25,
				ExternalID:      "ABC123",
				FieldsDecrypted: []string{"name", "age", "external_id"},
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "admin-user",
		Role:     "admin",
	}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	results, _, err := svc.Search(context.Background(), principal, reqCtx, "ABC123")

	// Assert
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Verify first spectator
	assert.Equal(t, "spectator-1", results[0].ID, "Admin should see unmasked ID")
	assert.Equal(t, "John Doe", results[0].Name)
	assert.Equal(t, 25, results[0].Age)
	assert.Equal(t, "ABC123", results[0].ExternalID)

	// Verify second spectator
	assert.Equal(t, "spectator-2", results[1].ID)
	assert.Equal(t, "Jane Smith", results[1].Name)

	// Verify HMAC lookup was called
	assert.Equal(t, 1, spectatorRepo.findByLookupCallCount)

	// Verify audit log
	require.Len(t, auditSvc.allAuditLogs, 1)
	assert.Equal(t, "search.spectator", auditSvc.allAuditLogs[0].Action)
	assert.Equal(t, "allow", auditSvc.allAuditLogs[0].Outcome)
	// Note: Decision hash not propagated from Evaluate (separate from Enforce pattern)
	assert.Equal(t, "", auditSvc.allAuditLogs[0].DecisionHash)
	// Python parity: audit includes matches count
	details := auditSvc.allAuditLogs[0].Details
	assert.Equal(t, 2, details["matches"])
}

func TestSpectatorService_Search_AgentFinds_PIIMasked(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{
		findByLookupResult: []*domain.Spectator{
			{
				TenantID:         "t1",
				ID:               "spectator-1",
				HallID:           "hall-1",
				NameCT:           "vault:v1:encrypted-name",
				AgeCT:            "vault:v1:encrypted-age",
				ExternalIDCT:     "vault:v1:encrypted-id",
				ExternalIDLookup: []byte("hmac-lookup"),
			},
		},
	}
	hallRepo := &fakeHallRepoForSpectator{}
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			return Decision{Allow: true, Hash: "hash"}, nil
		},
		shapeReadFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input spectatorRuleInput) (spectatorRuleResult, error) {
			// Agent sees age decrypted, PII masked
			return spectatorRuleResult{
				Name:            "J***",
				Age:             25,
				ExternalID:      "A***",
				FieldsDecrypted: []string{"age"},
				FieldsMasked:    []string{"name", "external_id"},
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "agent-user",
		Role:     "agent",
	}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	results, _, err := svc.Search(context.Background(), principal, reqCtx, "ABC123")

	// Assert
	require.NoError(t, err)
	require.Len(t, results, 1)

	spectator := results[0]
	assert.Equal(t, "J***", spectator.Name, "Agent should see masked name")
	assert.Equal(t, 25, spectator.Age, "Agent should see decrypted age")
	assert.Equal(t, "A***", spectator.ExternalID, "Agent should see masked external_id")

	// Verify spectator ID is masked for non-admin
	spectatorIDStr, ok := spectator.ID.(string)
	require.True(t, ok, "ID should be masked string for agent")
	assert.Contains(t, spectatorIDStr, "…", "Should be UUID masked format")
}

func TestSpectatorService_Search_DeveloperDenied(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{}
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			// Assuming developer is denied for search (verify with Python)
			return Decision{
				Allow:        false,
				Reason:       "search_forbidden",
				Hash: "hash-deny",
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1",
		UserID:   "dev-user",
		Role:     "developer",
	}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	_, _, err := svc.Search(context.Background(), principal, reqCtx, "ABC123")

	// Assert
	require.Error(t, err)
	assert.Equal(t, ErrForbidden, err)

	// Verify repo was not queried
	assert.Equal(t, 0, spectatorRepo.findByLookupCallCount)

	// Verify audit log shows deny
	require.Len(t, auditSvc.allAuditLogs, 1)
	assert.Equal(t, "search.spectator", auditSvc.allAuditLogs[0].Action)
	assert.Equal(t, "deny", auditSvc.allAuditLogs[0].Outcome)

	// Verify perf log was written even on deny
	assert.Equal(t, 1, perfWriter.calls)
}

func TestSpectatorService_Search_NoMatchesFound_ReturnsEmptyArray(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{
		findByLookupResult: []*domain.Spectator{}, // Empty - no matches
	}
	hallRepo := &fakeHallRepoForSpectator{}
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			return Decision{Allow: true, Hash: "hash"}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	results, _, err := svc.Search(context.Background(), principal, reqCtx, "NOTFOUND")

	// Assert
	require.NoError(t, err)
	assert.Empty(t, results, "Should return empty array when no matches found")

	// Verify audit log shows 0 matches
	require.Len(t, auditSvc.allAuditLogs, 1)
	details := auditSvc.allAuditLogs[0].Details
	assert.Equal(t, 0, details["matches"])
}

func TestSpectatorService_Search_PolicyEvaluationError_ReturnsError(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{}
	policyErr := errors.New("policy engine unavailable")
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			return Decision{}, policyErr
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	_, _, err := svc.Search(context.Background(), principal, reqCtx, "ABC123")

	// Assert
	require.Error(t, err)
	assert.ErrorIs(t, err, policyErr)
	assert.Equal(t, 0, spectatorRepo.findByLookupCallCount)
}

func TestSpectatorService_Search_PepperRetrievalError_ReturnsError(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{}
	hallRepo := &fakeHallRepoForSpectator{}
	pepperErr := errors.New("vault kv read failed")
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			return Decision{Allow: true, Hash: "hash"}, nil
		},
		pepperFunc: func(ctx context.Context, path string) ([]byte, error) {
			return nil, pepperErr
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	_, _, err := svc.Search(context.Background(), principal, reqCtx, "ABC123")

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get pepper")
	assert.Equal(t, 0, spectatorRepo.findByLookupCallCount)
}

func TestSpectatorService_Search_RepositoryError_ReturnsError(t *testing.T) {
	// Arrange
	dbErr := errors.New("database connection lost")
	spectatorRepo := &fakeSpectatorRepo{
		findByLookupErr: dbErr,
	}
	hallRepo := &fakeHallRepoForSpectator{}
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			return Decision{Allow: true, Hash: "hash"}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{TenantID: "t1", UserID: "user-1", Role: "admin"}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	_, _, err := svc.Search(context.Background(), principal, reqCtx, "ABC123")

	// Assert
	require.Error(t, err)
	assert.Equal(t, dbErr, err)
}

func TestSpectatorService_Search_TenantIsolation(t *testing.T) {
	// Arrange
	spectatorRepo := &fakeSpectatorRepo{
		findByLookupResult: []*domain.Spectator{
			{TenantID: "t1", ID: "spectator-1", HallID: "hall-1"},
			{TenantID: "t2", ID: "spectator-2", HallID: "hall-2"}, // Different tenant
		},
	}
	hallRepo := &fakeHallRepoForSpectator{}
	rules := &fakeSpectatorRules{
		authorizeSearchFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
			return Decision{Allow: true, Hash: "hash"}, nil
		},
		shapeReadFunc: func(ctx context.Context, principal Principal, reqCtx RequestContext, input spectatorRuleInput) (spectatorRuleResult, error) {
			return spectatorRuleResult{
				Name:       "Test",
				Age:        25,
				ExternalID: "ABC",
			}, nil
		},
	}
	auditSvc := &mockAuditService{}
	perfWriter := &fakePerfWriter{}
	runtime := fakeRuntimeSettings{dcsEnabled: true, cacheLevel: 2}

	svc := newSpectatorServiceForTest(spectatorRepo, hallRepo, rules, auditSvc, perfWriter, runtime)

	principal := Principal{
		TenantID: "t1", // Search as tenant t1
		UserID:   "user-1",
		Role:     "admin",
	}
	reqCtx := RequestContext{RequestID: "req-search"}

	// Act
	results, _, err := svc.Search(context.Background(), principal, reqCtx, "ABC123")

	// Assert
	require.NoError(t, err)
	// Should only return spectator from tenant t1, not t2
	require.Len(t, results, 1, "Should filter by tenant")
	assert.Equal(t, "hall-1", results[0].HallID)
}
