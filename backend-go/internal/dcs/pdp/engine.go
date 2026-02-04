package pdp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type Engine struct {
	runtime *runtime.Settings
	cache   *cache.Manager
}

func NewEngine(rt *runtime.Settings, cm *cache.Manager) *Engine {
	return &Engine{
		runtime: rt,
		cache:   cm,
	}
}

func (e *Engine) Evaluate(input types.PolicyInput) (types.Decision, bool) {
	cacheable := e.cache.LevelEnabled(2) && (input.Action == "film.read" || input.Action == "film.update_time")
	cacheKey := ""
	if cacheable {
		cacheKey = decisionCacheKey(e.runtime.DcsEnabled(), input)
		if cached, ok := e.cache.PDP.Get(cacheKey); ok {
			return cached, true
		}
	}

	var decision types.Decision
	if !e.runtime.DcsEnabled() {
		decision = types.Decision{
			Allow:        allowWithoutDCS(input.Action, input.Principal.Role),
			FieldActions: map[string]types.FieldAction{},
			Reason:       "dcs_off",
		}
	} else {
		decision = decide(input)
	}

	if cacheable {
		e.cache.PDP.Set(cacheKey, decision, 0)
	}
	return decision, false
}

func DecisionHash(decision types.Decision) string {
	raw, _ := json.Marshal(decision)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func decide(input types.PolicyInput) types.Decision {
	if input.Principal.TenantID != input.Resource.TenantID {
		return types.Decision{Allow: false, FieldActions: map[string]types.FieldAction{}, Reason: "tenant_mismatch"}
	}

	allow := false
	reason := "default_deny"
	switch input.Action {
	case "film.read", "hall.read", "spectator.read", "search.spectator":
		allow = true
		reason = "read_allowed"
	case "film.create", "hall.create", "spectator.create", "film.update_time":
		allow = input.Principal.Role == "agent" || input.Principal.Role == "admin"
		if allow {
			reason = "write_allowed"
		} else {
			reason = "write_forbidden"
		}
	case "audit.read":
		allow = input.Principal.Role == "admin"
		if allow {
			reason = "audit_allowed"
		} else {
			reason = "audit_admin_only"
		}
	default:
		return types.Decision{Allow: false, FieldActions: map[string]types.FieldAction{}, Reason: "unknown_action"}
	}
	if !allow {
		return types.Decision{Allow: false, FieldActions: map[string]types.FieldAction{}, Reason: reason}
	}

	fieldActions := map[string]types.FieldAction{}
	for field, meta := range input.Resource.Fields {
		fieldActions[field] = actionForClassification(input.Principal.Role, meta.Classification)
	}

	if input.Resource.Type == "spectator" && input.Principal.Role == "agent" {
		for _, fn := range []string{"name", "external_id"} {
			if _, ok := fieldActions[fn]; ok {
				fieldActions[fn] = types.FieldActionMaskAfterDecrypt
			}
		}
	}
	return types.Decision{Allow: true, FieldActions: fieldActions, Reason: reason}
}

func actionForClassification(role string, cls types.Classification) types.FieldAction {
	switch strings.ToLower(role) {
	case "admin":
		switch cls {
		case types.ClassificationSensitive, types.ClassificationPII:
			return types.FieldActionDecrypt
		default:
			return types.FieldActionAllow
		}
	case "agent":
		switch cls {
		case types.ClassificationPII:
			return types.FieldActionMaskAfterDecrypt
		case types.ClassificationSensitive:
			return types.FieldActionDecrypt
		default:
			return types.FieldActionAllow
		}
	case "developer":
		switch cls {
		case types.ClassificationPublic:
			return types.FieldActionAllow
		default:
			return types.FieldActionMaskAfterDecrypt
		}
	default:
		return types.FieldActionDeny
	}
}

func allowWithoutDCS(action, role string) bool {
	switch action {
	case "film.read", "hall.read", "spectator.read", "search.spectator":
		return true
	case "film.create", "hall.create", "spectator.create", "film.update_time":
		return role == "agent" || role == "admin"
	case "audit.read":
		return role == "admin"
	default:
		return false
	}
}

func decisionCacheKey(dcsEnabled bool, input types.PolicyInput) string {
	fields := make([]string, 0, len(input.Resource.Fields))
	for k, v := range input.Resource.Fields {
		fields = append(fields, k+":"+string(v.Classification))
	}
	sort.Strings(fields)

	labels := append([]string(nil), input.Resource.Labels...)
	sort.Strings(labels)

	payload := map[string]any{
		"dcs":      dcsEnabled,
		"action":   input.Action,
		"tenant":   input.Principal.TenantID,
		"role":     input.Principal.Role,
		"user":     input.Principal.UserID,
		"resource": input.Resource.Type,
		"owner":    input.Resource.OwnerID,
		"labels":   labels,
		"fields":   fields,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
