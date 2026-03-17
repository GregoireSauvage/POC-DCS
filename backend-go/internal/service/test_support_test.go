package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	securitymask "github.com/neoweyss/poc-dcs/backend-go/internal/security/mask"
)

type mockAuditService struct {
	writeCalls   int
	lastAuditLog *domain.AuditLog
	allAuditLogs []*domain.AuditLog
	writeError   error
}

func (m *mockAuditService) WriteAudit(_ context.Context, log *domain.AuditLog) error {
	if m == nil {
		return nil
	}
	m.writeCalls++
	m.lastAuditLog = log
	m.allAuditLogs = append(m.allAuditLogs, log)
	return m.writeError
}

type fakePerfWriter struct {
	calls    int
	lastPerf *domain.PerfLog
	writeErr error
}

func (f *fakePerfWriter) Write(_ context.Context, log *domain.PerfLog) error {
	f.calls++
	f.lastPerf = log
	return f.writeErr
}

type fakeRuntimeSettings struct {
	dcsEnabled bool
	cacheLevel int
}

func (f fakeRuntimeSettings) DcsEnabled() bool { return f.dcsEnabled }
func (f fakeRuntimeSettings) CacheLevel() int  { return f.cacheLevel }

type spectatorCreatePayload struct {
	HallID     string
	Name       string
	Age        int
	ExternalID string
}

type spectatorEncryptedPayload struct {
	HallID           string
	NameCT           string
	AgeCT            string
	ExternalIDCT     string
	ExternalIDLookup []byte
}

type spectatorRuleInput struct {
	SpectatorID  string
	HallID       string
	NameCT       string
	AgeCT        string
	ExternalIDCT string
}

type spectatorRuleResult struct {
	Name            interface{}
	Age             interface{}
	ExternalID      interface{}
	FieldsDecrypted []string
	FieldsMasked    []string
	FieldsDenied    []string
	DecisionHash    string
	PolicyID        string
	PolicyVersion   string
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

type fakeSpectatorRules struct {
	authorizeCreateFunc func(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (Decision, error)
	authorizeSearchFunc func(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error)
	shapeReadFunc       func(ctx context.Context, principal Principal, reqCtx RequestContext, spectator spectatorRuleInput) (spectatorRuleResult, error)
	encryptCreateFunc   func(ctx context.Context, principal Principal, reqCtx RequestContext, input spectatorCreatePayload) (spectatorEncryptedPayload, error)
	pepperFunc          func(ctx context.Context, path string) ([]byte, error)
}

func (f *fakeSpectatorRules) authorizeCreate(ctx context.Context, principal Principal, reqCtx RequestContext, ownerUserID string) (Decision, error) {
	if f.authorizeCreateFunc != nil {
		return f.authorizeCreateFunc(ctx, principal, reqCtx, ownerUserID)
	}
	return Decision{Allow: true, Reason: "test"}, nil
}

func (f *fakeSpectatorRules) authorizeSearch(ctx context.Context, principal Principal, reqCtx RequestContext) (Decision, error) {
	if f.authorizeSearchFunc != nil {
		return f.authorizeSearchFunc(ctx, principal, reqCtx)
	}
	return Decision{Allow: true, Reason: "test"}, nil
}

func (f *fakeSpectatorRules) shapeRead(ctx context.Context, principal Principal, reqCtx RequestContext, spectator spectatorRuleInput) (spectatorRuleResult, error) {
	if f.shapeReadFunc != nil {
		return f.shapeReadFunc(ctx, principal, reqCtx, spectator)
	}
	return spectatorRuleResult{}, nil
}

func (f *fakeSpectatorRules) encryptCreate(ctx context.Context, principal Principal, reqCtx RequestContext, input spectatorCreatePayload) (spectatorEncryptedPayload, error) {
	if f.encryptCreateFunc != nil {
		return f.encryptCreateFunc(ctx, principal, reqCtx, input)
	}
	if f.authorizeCreateFunc != nil {
		decision, err := f.authorizeCreateFunc(ctx, principal, reqCtx, "")
		if err != nil {
			return spectatorEncryptedPayload{}, err
		}
		if !decision.Allow {
			return spectatorEncryptedPayload{}, ErrForbidden
		}
	}
	return spectatorEncryptedPayload{
		HallID:           input.HallID,
		NameCT:           "vault:v1:encrypted",
		AgeCT:            "vault:v1:encrypted",
		ExternalIDCT:     "vault:v1:encrypted",
		ExternalIDLookup: []byte("lookup"),
	}, nil
}

func (f *fakeSpectatorRules) pepper(ctx context.Context, path string) ([]byte, error) {
	if f.pepperFunc != nil {
		return f.pepperFunc(ctx, path)
	}
	return []byte("test-pepper"), nil
}

func newSpectatorServiceForTest(
	spectatorRepo *fakeSpectatorRepo,
	hallRepo *fakeHallRepoForSpectator,
	rules *fakeSpectatorRules,
	audit AuditWriter,
	perf PerfWriter,
	runtime RuntimeSettings,
) *SpectatorService {
	return NewSpectatorService(
		&testSpectatorRepo{raw: spectatorRepo, rules: rules, runtime: runtime},
		hallRepo,
		&testSpectatorAuthorizer{rules: rules},
		nil,
		audit,
		perf,
		runtime,
	)
}

type testSpectatorRepo struct {
	raw     *fakeSpectatorRepo
	rules   *fakeSpectatorRules
	runtime RuntimeSettings
}

func (r *testSpectatorRepo) Create(ctx context.Context, tenantID string, input SpectatorCreateInput, decision Decision) (SpectatorReadCandidate, error) {
	if !decision.Allow {
		return SpectatorReadCandidate{}, ErrForbidden
	}
	access, _ := AccessContextFromContext(ctx)
	encrypted, err := r.rules.encryptCreate(ctx, access.Principal, access.Request, spectatorCreatePayload{
		HallID:     input.HallID,
		Name:       input.Name,
		Age:        input.Age,
		ExternalID: input.ExternalID,
	})
	if err != nil {
		return SpectatorReadCandidate{}, err
	}
	spectator := &domain.Spectator{
		TenantID:         tenantID,
		ID:               uuid.New().String(),
		HallID:           encrypted.HallID,
		NameCT:           encrypted.NameCT,
		AgeCT:            encrypted.AgeCT,
		ExternalIDCT:     encrypted.ExternalIDCT,
		ExternalIDLookup: encrypted.ExternalIDLookup,
	}
	if err := r.raw.Create(ctx, spectator); err != nil {
		return SpectatorReadCandidate{}, err
	}
	resource, err := BuildSpectatorReadResource(ctx, nil, spectator)
	if err != nil {
		return SpectatorReadCandidate{}, err
	}
	return SpectatorReadCandidate{Record: spectator, Resource: resource}, nil
}

func (r *testSpectatorRepo) SearchCandidatesByExternalID(ctx context.Context, tenantID string, externalID string, decision Decision) ([]SpectatorReadCandidate, error) {
	if !decision.Allow {
		return nil, ErrForbidden
	}
	pepper, err := r.rules.pepper(ctx, DefaultSpectatorPepperPath)
	if err != nil {
		return nil, fmt.Errorf("get pepper: %w", err)
	}
	lookup := ComputeHMACLookup(pepper, NormalizeExternalID(externalID))
	spectators, err := r.raw.FindByExternalIDLookup(ctx, tenantID, lookup)
	if err != nil {
		return nil, err
	}
	out := make([]SpectatorReadCandidate, 0, len(spectators))
	for _, spectator := range spectators {
		resource, err := BuildSpectatorReadResource(ctx, nil, spectator)
		if err != nil {
			return nil, err
		}
		out = append(out, SpectatorReadCandidate{Record: spectator, Resource: resource})
	}
	return out, nil
}

func (r *testSpectatorRepo) ApplyReadDecision(ctx context.Context, candidate SpectatorReadCandidate, decision Decision) (SpectatorReadView, error) {
	if !decision.Allow {
		return SpectatorReadView{}, ErrForbidden
	}
	access, _ := AccessContextFromContext(ctx)
	result, err := r.rules.shapeRead(ctx, access.Principal, access.Request, spectatorRuleInput{
		SpectatorID:  candidate.Record.ID,
		HallID:       candidate.Record.HallID,
		NameCT:       candidate.Record.NameCT,
		AgeCT:        candidate.Record.AgeCT,
		ExternalIDCT: candidate.Record.ExternalIDCT,
	})
	if err != nil {
		return SpectatorReadView{}, err
	}
	var spectatorIDOutput interface{} = candidate.Record.ID
	if r.runtime != nil && r.runtime.DcsEnabled() && access.Principal.Role != "admin" {
		spectatorIDOutput = securitymask.UUID(candidate.Record.ID)
	}
	return SpectatorReadView{
		Output: SpectatorOutput{
			ID:         spectatorIDOutput,
			HallID:     candidate.Record.HallID,
			Name:       result.Name,
			Age:        result.Age,
			ExternalID: result.ExternalID,
		},
		DecisionHash:    result.DecisionHash,
		PolicyID:        result.PolicyID,
		PolicyVersion:   result.PolicyVersion,
		FieldsDecrypted: result.FieldsDecrypted,
		FieldsMasked:    result.FieldsMasked,
		FieldsDenied:    result.FieldsDenied,
	}, nil
}

type testSpectatorAuthorizer struct {
	rules *fakeSpectatorRules
}

func (a *testSpectatorAuthorizer) Authorize(ctx context.Context, input PolicyInput) (Decision, error) {
	access, _ := AccessContextFromContext(ctx)
	switch input.Access.Action {
	case ActionSpectatorCreate:
		return a.rules.authorizeCreate(ctx, access.Principal, access.Request, input.Resource.OwnerID)
	case ActionSearchSpectator:
		return a.rules.authorizeSearch(ctx, access.Principal, access.Request)
	case ActionSpectatorRead:
		return Decision{Allow: true}, nil
	default:
		return Decision{}, nil
	}
}
