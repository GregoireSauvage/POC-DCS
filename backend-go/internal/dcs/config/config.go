// Package config is a legacy compatibility shim.
// Deprecated: use github.com/neoweyss/poc-dcs/backend-go/internal/config.
package config

import (
	canonicalconfig "github.com/neoweyss/poc-dcs/backend-go/internal/config"
	legacytypes "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type DCSConfig struct {
	Policy PolicyConfig `json:"policy"`
	PIP    PIPConfig    `json:"pip"`
	PDP    PDPConfig    `json:"pdp"`
}

type PolicyConfig struct {
	PolicyID            string                       `json:"policy_id"`
	PolicyVersion       string                       `json:"policy_version"`
	ClassificationOrder []legacytypes.Classification `json:"classification_order"`
	AllowedCategories   []string                     `json:"allowed_categories"`
	Markings            map[string]string            `json:"markings"`
}

type PIPConfig struct {
	Channel        string  `json:"channel"`
	Purpose        string  `json:"purpose"`
	DeviceTrust    float64 `json:"device_trust"`
	ClientIPHeader string  `json:"client_ip_header"`
}

type PDPConfig struct {
	DefaultClassification         legacytypes.Classification   `json:"default_classification"`
	ReadActions                   []string                     `json:"read_actions"`
	WriteActions                  []string                     `json:"write_actions"`
	BootstrapActions              []string                     `json:"bootstrap_actions"`
	AuditActions                  []string                     `json:"audit_actions"`
	RoleClassificationActions     map[string]map[string]string `json:"role_classification_actions"`
	SpectatorAgentHardeningFields []string                     `json:"spectator_agent_hardening_fields"`
	PolicyID                      string                       `json:"-"`
	PolicyVersion                 string                       `json:"-"`
}

// Deprecated: use internal/config.LoadDCSConfig.
func Load(path string) (*DCSConfig, error) {
	cfg, err := canonicalconfig.LoadDCSConfig(path)
	if err != nil {
		return nil, err
	}
	return fromCanonical(cfg), nil
}

// Deprecated: use internal/config.DefaultDCSConfig.
func Defaults() *DCSConfig {
	return fromCanonical(canonicalconfig.DefaultDCSConfig())
}

func fromCanonical(cfg *canonicalconfig.DCSConfig) *DCSConfig {
	if cfg == nil {
		cfg = canonicalconfig.DefaultDCSConfig()
	}

	out := &DCSConfig{
		Policy: PolicyConfig{
			PolicyID:            cfg.Policy.PolicyID,
			PolicyVersion:       cfg.Policy.PolicyVersion,
			ClassificationOrder: make([]legacytypes.Classification, 0, len(cfg.Policy.ClassificationOrder)),
			AllowedCategories:   append([]string(nil), cfg.Policy.AllowedCategories...),
			Markings:            cloneStringMap(cfg.Policy.Markings),
		},
		PIP: PIPConfig{
			Channel:        cfg.PIP.Channel,
			Purpose:        cfg.PIP.Purpose,
			DeviceTrust:    cfg.PIP.DeviceTrust,
			ClientIPHeader: cfg.PIP.ClientIPHeader,
		},
		PDP: PDPConfig{
			DefaultClassification:         legacytypes.Classification(cfg.PDP.DefaultClassification),
			ReadActions:                   append([]string(nil), cfg.PDP.ReadActions...),
			WriteActions:                  append([]string(nil), cfg.PDP.WriteActions...),
			BootstrapActions:              append([]string(nil), cfg.PDP.BootstrapActions...),
			AuditActions:                  append([]string(nil), cfg.PDP.AuditActions...),
			RoleClassificationActions:     cloneNestedStringMap(cfg.PDP.RoleClassificationActions),
			SpectatorAgentHardeningFields: append([]string(nil), cfg.PDP.SpectatorAgentHardeningFields...),
			PolicyID:                      cfg.Policy.PolicyID,
			PolicyVersion:                 cfg.Policy.PolicyVersion,
		},
	}

	for _, cls := range cfg.Policy.ClassificationOrder {
		out.Policy.ClassificationOrder = append(out.Policy.ClassificationOrder, legacytypes.Classification(cls))
	}

	return out
}

func cloneStringMap(src map[string]string) map[string]string {
	if src == nil {
		return map[string]string{}
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func cloneNestedStringMap(src map[string]map[string]string) map[string]map[string]string {
	if src == nil {
		return map[string]map[string]string{}
	}
	dst := make(map[string]map[string]string, len(src))
	for key, values := range src {
		inner := make(map[string]string, len(values))
		for innerKey, innerValue := range values {
			inner[innerKey] = innerValue
		}
		dst[key] = inner
	}
	return dst
}
