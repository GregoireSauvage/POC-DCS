package pdp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	dcsconfig "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type Engine struct {
	runtime *runtime.Settings
	cache   *cache.Manager
	config  *dcsconfig.PDPConfig
}

func NewEngine(rt *runtime.Settings, cm *cache.Manager, cfg *dcsconfig.PDPConfig) *Engine {
	return &Engine{
		runtime: rt,
		cache:   cm,
		config:  cfg,
	}
}

func (e *Engine) Evaluate(input types.PolicyInput) (types.Decision, bool) {
	cacheable := e.cache.LevelEnabled(2) && (input.Action == "film.read" || input.Action == "film.update_time" || input.Action == "film.create")
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
			Allow:        e.allowWithoutDCS(input.Action, input.Principal.Role),
			FieldActions: map[string]types.FieldAction{},
			Reason:       "dcs_off",
		}
	} else {
		decision = e.decide(input)
	}

	// Compute decision hash for audit correlation
	decision.Hash = DecisionHash(decision)

	if cacheable {
		e.cache.PDP.Set(cacheKey, decision, 0)
	}
	return decision, false
}

// DecisionHash computes a deterministic SHA256 hash of a decision.
// Field actions are sorted by key to ensure the same decision always produces the same hash,
// matching Python's json.dumps(sort_keys=True) behavior.
//
// NOTE: Uses compact JSON format (no spaces) for better performance.
// This differs from Python's default json.dumps() which adds spaces after : and ,
// If strict parity with existing Python audit logs is required, use MarshalIndent with custom separator.
func DecisionHash(decision types.Decision) string {
	// Sort field_actions keys to ensure deterministic output
	fieldKeys := make([]string, 0, len(decision.FieldActions))
	for k := range decision.FieldActions {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)

	// Build sorted map to guarantee consistent JSON marshaling
	sortedActions := make(map[string]types.FieldAction, len(decision.FieldActions))
	for _, k := range fieldKeys {
		sortedActions[k] = decision.FieldActions[k]
	}

	// Create payload matching Python's structure
	payload := map[string]interface{}{
		"allow":         decision.Allow,
		"field_actions": sortedActions,
		"reason":        decision.Reason,
	}

	// Use compact JSON format (matches Go's default json.Marshal)
	// This is more efficient than Python's default which adds spaces
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (e *Engine) decide(input types.PolicyInput) types.Decision {
	if input.Principal.TenantID != input.Resource.TenantID {
		return types.Decision{Allow: false, FieldActions: map[string]types.FieldAction{}, Reason: "tenant_mismatch"}
	}

	// Determine if action is allowed based on config action lists
	allow := false
	reason := "default_deny"

	if contains(e.config.ReadActions, input.Action) {
		allow = true
		reason = "read_allowed"
	} else if contains(e.config.WriteActions, input.Action) {
		allow = input.Principal.Role == "agent" || input.Principal.Role == "admin"
		if allow {
			reason = "write_allowed"
		} else {
			reason = "write_forbidden"
		}
	} else if contains(e.config.BootstrapActions, input.Action) {
		allow = true
		reason = "bootstrap_allowed"
	} else if contains(e.config.AuditActions, input.Action) {
		allow = input.Principal.Role == "admin"
		if allow {
			reason = "audit_allowed"
		} else {
			reason = "audit_admin_only"
		}
	} else {
		return types.Decision{Allow: false, FieldActions: map[string]types.FieldAction{}, Reason: "unknown_action"}
	}

	if !allow {
		return types.Decision{Allow: false, FieldActions: map[string]types.FieldAction{}, Reason: reason}
	}

	// Build field actions using config-driven matrix
	fieldActions := map[string]types.FieldAction{}
	for field, meta := range input.Resource.Fields {
		// Apply default classification if missing
		classification := meta.Classification
		if classification == "" {
			classification = e.config.DefaultClassification
		}
		fieldActions[field] = e.actionForClassification(input.Principal.Role, classification)
	}

	// Apply spectator agent hardening from config
	if input.Resource.Type == "spectator" && input.Principal.Role == "agent" {
		for _, fn := range e.config.SpectatorAgentHardeningFields {
			if _, ok := fieldActions[fn]; ok {
				fieldActions[fn] = types.FieldActionMaskAfterDecrypt
			}
		}
	}

	return types.Decision{Allow: true, FieldActions: fieldActions, Reason: reason}
}

func (e *Engine) actionForClassification(role string, cls types.Classification) types.FieldAction {
	// Lookup in config matrix: role -> classification -> action string
	roleMatrix, ok := e.config.RoleClassificationActions[strings.ToLower(role)]
	if !ok {
		return types.FieldActionDeny
	}

	actionStr, ok := roleMatrix[string(cls)]
	if !ok {
		return types.FieldActionDeny
	}

	// Convert action string to FieldAction type
	return parseFieldAction(actionStr)
}

func parseFieldAction(s string) types.FieldAction {
	switch s {
	case "allow":
		return types.FieldActionAllow
	case "decrypt":
		return types.FieldActionDecrypt
	case "mask_after_decrypt":
		return types.FieldActionMaskAfterDecrypt
	case "deny":
		return types.FieldActionDeny
	default:
		return types.FieldActionDeny
	}
}

func (e *Engine) allowWithoutDCS(action, role string) bool {
	// Read actions: always allowed
	if contains(e.config.ReadActions, action) {
		return true
	}

	// Write actions: agent/admin only
	if contains(e.config.WriteActions, action) {
		return role == "agent" || role == "admin"
	}

	// Bootstrap actions: always allowed
	if contains(e.config.BootstrapActions, action) {
		return true
	}

	// Audit actions: admin only
	if contains(e.config.AuditActions, action) {
		return role == "admin"
	}

	return false
}

// contains checks if a string slice contains a specific value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
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
