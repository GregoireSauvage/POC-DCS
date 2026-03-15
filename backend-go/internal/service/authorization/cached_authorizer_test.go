package authorization

import (
	"context"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type fakeRuntime struct {
	enabled bool
	level   int
}

func (f fakeRuntime) DcsEnabled() bool { return f.enabled }
func (f fakeRuntime) CacheLevel() int  { return f.level }

type countingAuthorizer struct {
	calls    int
	decision service.Decision
}

func (c *countingAuthorizer) Authorize(ctx context.Context, input service.PolicyInput) (service.Decision, error) {
	_ = ctx
	_ = input
	c.calls++
	return c.decision, nil
}

type mapDecisionCache struct {
	values map[string]service.Decision
}

func (m *mapDecisionCache) Get(key string) (service.Decision, bool) {
	decision, ok := m.values[key]
	return decision, ok
}

func (m *mapDecisionCache) Set(key string, value service.Decision) {
	m.values[key] = value
}

func TestCachedAuthorizer_CachesFilmRead(t *testing.T) {
	delegate := &countingAuthorizer{decision: service.Decision{Allow: true, Reason: "read_allowed"}}
	cache := &mapDecisionCache{values: map[string]service.Decision{}}
	authorizer := NewCachedAuthorizer(fakeRuntime{enabled: true, level: 2}, cache, delegate)
	input := buildTestInput(service.ActionFilmRead, "admin", "film", "t1", map[string]service.FieldMeta{"field": {Classification: service.ClassificationPublic}})

	if _, err := authorizer.Authorize(context.Background(), input); err != nil {
		t.Fatalf("first authorize returned error: %v", err)
	}
	if _, err := authorizer.Authorize(context.Background(), input); err != nil {
		t.Fatalf("second authorize returned error: %v", err)
	}
	if delegate.calls != 1 {
		t.Fatalf("expected cached delegate to be called once, got %d", delegate.calls)
	}
}

func TestCachedAuthorizer_DoesNotCacheHallRead(t *testing.T) {
	delegate := &countingAuthorizer{decision: service.Decision{Allow: true, Reason: "read_allowed"}}
	cache := &mapDecisionCache{values: map[string]service.Decision{}}
	authorizer := NewCachedAuthorizer(fakeRuntime{enabled: true, level: 2}, cache, delegate)
	input := buildTestInput(service.ActionHallRead, "admin", "hall", "t1", map[string]service.FieldMeta{"field": {Classification: service.ClassificationPublic}})

	_, _ = authorizer.Authorize(context.Background(), input)
	_, _ = authorizer.Authorize(context.Background(), input)
	if delegate.calls != 2 {
		t.Fatalf("expected uncached delegate to be called twice, got %d", delegate.calls)
	}
}

func TestDecisionCacheKey_Stable(t *testing.T) {
	inputA := service.PolicyInput{
		Access: service.AccessContext{
			Principal: service.Principal{TenantID: "t1", UserID: "u1", Role: "admin"},
			Action:    service.ActionFilmRead,
		},
		Resource: service.Resource{
			Type:    "film",
			OwnerID: "owner-1",
			Labels:  []string{"b", "a"},
			Fields: map[string]service.FieldMeta{
				"z": {Classification: service.ClassificationSensitive},
				"a": {Classification: service.ClassificationPublic},
			},
		},
	}
	inputB := service.PolicyInput{
		Access: inputA.Access,
		Resource: service.Resource{
			Type:    "film",
			OwnerID: "owner-1",
			Labels:  []string{"a", "b"},
			Fields: map[string]service.FieldMeta{
				"a": {Classification: service.ClassificationPublic},
				"z": {Classification: service.ClassificationSensitive},
			},
		},
	}

	if keyA, keyB := decisionCacheKey(true, inputA), decisionCacheKey(true, inputB); keyA != keyB {
		t.Fatalf("expected stable cache key, got %q and %q", keyA, keyB)
	}
}

func TestPolicyAuthorizer_DCSOff(t *testing.T) {
	policy := buildTestPolicy()
	authorizer := NewAuthorizer(fakeRuntime{enabled: false, level: 0}, NewPDP(policy))
	decision, err := authorizer.Authorize(context.Background(), buildTestInput(service.ActionFilmRead, "developer", "film", "t1", nil))
	if err != nil {
		t.Fatalf("authorize returned error: %v", err)
	}
	if !decision.Allow {
		t.Fatalf("expected dcs_off read to allow")
	}
	if decision.Reason != "dcs_off" {
		t.Fatalf("expected dcs_off reason, got %q", decision.Reason)
	}
}
