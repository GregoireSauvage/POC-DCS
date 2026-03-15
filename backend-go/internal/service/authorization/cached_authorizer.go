package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type DecisionCache interface {
	Get(key string) (service.Decision, bool)
	Set(key string, value service.Decision)
}

type CachedAuthorizer struct {
	runtime  service.RuntimeSettings
	delegate service.Authorizer
	cache    DecisionCache
}

func NewCachedAuthorizer(runtime service.RuntimeSettings, cache DecisionCache, delegate service.Authorizer) *CachedAuthorizer {
	return &CachedAuthorizer{
		runtime:  runtime,
		cache:    cache,
		delegate: delegate,
	}
}

func (a *CachedAuthorizer) Authorize(ctx context.Context, input service.PolicyInput) (service.Decision, error) {
	if a.delegate == nil {
		return service.Decision{}, nil
	}
	if a.runtime == nil || a.cache == nil || a.runtime.CacheLevel() < 2 || !cacheableAction(input.Access.Action) {
		return a.delegate.Authorize(ctx, input)
	}

	cacheKey := decisionCacheKey(a.runtime.DcsEnabled(), input)
	if cached, ok := a.cache.Get(cacheKey); ok {
		return cached, nil
	}

	decision, err := a.delegate.Authorize(ctx, input)
	if err != nil {
		return service.Decision{}, err
	}
	a.cache.Set(cacheKey, decision)
	return decision, nil
}

func cacheableAction(action service.Action) bool {
	switch action {
	case service.ActionFilmRead, service.ActionFilmUpdateTime, service.ActionFilmCreate:
		return true
	default:
		return false
	}
}

func decisionCacheKey(dcsEnabled bool, input service.PolicyInput) string {
	fields := make([]string, 0, len(input.Resource.Fields))
	for key, value := range input.Resource.Fields {
		fields = append(fields, key+":"+string(value.Classification))
	}
	sort.Strings(fields)

	labels := append([]string(nil), input.Resource.Labels...)
	sort.Strings(labels)

	payload := map[string]any{
		"dcs":      dcsEnabled,
		"action":   input.Access.Action,
		"tenant":   input.Access.Principal.TenantID,
		"role":     input.Access.Principal.Role,
		"user":     input.Access.Principal.UserID,
		"resource": input.Resource.Type,
		"owner":    input.Resource.OwnerID,
		"labels":   labels,
		"fields":   fields,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
