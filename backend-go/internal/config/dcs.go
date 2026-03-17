package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type DCSConfig struct {
	Policy  PolicyConfig  `json:"policy"`
	Binding BindingConfig `json:"binding"`
	PIP     PIPConfig     `json:"pip"`
	PDP     PDPConfig     `json:"pdp"`
}

type PolicyConfig struct {
	PolicyID            string                   `json:"policy_id"`
	PolicyVersion       string                   `json:"policy_version"`
	ClassificationOrder []service.Classification `json:"classification_order"`
	AllowedCategories   []string                 `json:"allowed_categories"`
	Markings            map[string]string        `json:"markings"`
}

type PIPConfig struct {
	Channel        string  `json:"channel"`
	Purpose        string  `json:"purpose"`
	DeviceTrust    float64 `json:"device_trust"`
	ClientIPHeader string  `json:"client_ip_header"`
}

type BindingConfig struct {
	ProfileID      string `json:"profile_id"`
	ProofAlgorithm string `json:"proof_algorithm"`
	KeyID          string `json:"key_id"`
}

type PDPConfig struct {
	DefaultClassification         service.Classification       `json:"default_classification"`
	ReadActions                   []string                     `json:"read_actions"`
	WriteActions                  []string                     `json:"write_actions"`
	BootstrapActions              []string                     `json:"bootstrap_actions"`
	AuditActions                  []string                     `json:"audit_actions"`
	RoleClassificationActions     map[string]map[string]string `json:"role_classification_actions"`
	SpectatorAgentHardeningFields []string                     `json:"spectator_agent_hardening_fields"`
}

func LoadDCSConfig(path string) (*DCSConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("DCS_CONFIG_PATH not specified")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg DCSConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	applyDCSDefaults(&cfg)
	return &cfg, nil
}

func DefaultDCSConfig() *DCSConfig {
	cfg := &DCSConfig{
		Policy: PolicyConfig{
			PolicyID:            "cinema-default",
			PolicyVersion:       "v1",
			ClassificationOrder: []service.Classification{service.ClassificationPublic, service.ClassificationInternal, service.ClassificationSensitive, service.ClassificationPII},
			AllowedCategories:   []string{},
			Markings:            map[string]string{},
		},
		Binding: BindingConfig{
			ProfileID:      "internal/bdo-hmac-v1",
			ProofAlgorithm: "hmac-sha256",
			KeyID:          "binding-key-v1",
		},
		PIP: PIPConfig{
			Channel:        "web",
			Purpose:        "cinema_ops",
			DeviceTrust:    0.8,
			ClientIPHeader: "x-real-ip",
		},
		PDP: PDPConfig{
			DefaultClassification: service.ClassificationInternal,
			ReadActions:           []string{"film.read", "hall.read", "spectator.read"},
			WriteActions:          []string{"film.create", "hall.create", "spectator.create", "film.update_time", "search.spectator"},
			BootstrapActions:      []string{"bootstrap"},
			AuditActions:          []string{"audit.read", "perf.read"},
			RoleClassificationActions: map[string]map[string]string{
				"admin": {
					"PUBLIC":    "allow",
					"INTERNAL":  "allow",
					"SENSITIVE": "decrypt",
					"PII":       "decrypt",
				},
				"agent": {
					"PUBLIC":    "allow",
					"INTERNAL":  "allow",
					"SENSITIVE": "decrypt",
					"PII":       "mask_after_decrypt",
				},
				"developer": {
					"PUBLIC":    "allow",
					"INTERNAL":  "mask_after_decrypt",
					"SENSITIVE": "mask_after_decrypt",
					"PII":       "mask_after_decrypt",
				},
			},
			SpectatorAgentHardeningFields: []string{"name", "external_id"},
		},
	}
	return cfg
}

func applyDCSDefaults(cfg *DCSConfig) {
	defaults := DefaultDCSConfig()
	if cfg.Policy.PolicyID == "" {
		cfg.Policy.PolicyID = defaults.Policy.PolicyID
	}
	if cfg.Policy.PolicyVersion == "" {
		cfg.Policy.PolicyVersion = defaults.Policy.PolicyVersion
	}
	if len(cfg.Policy.ClassificationOrder) == 0 {
		cfg.Policy.ClassificationOrder = append([]service.Classification(nil), defaults.Policy.ClassificationOrder...)
	}
	if cfg.Policy.AllowedCategories == nil {
		cfg.Policy.AllowedCategories = append([]string(nil), defaults.Policy.AllowedCategories...)
	}
	if cfg.Policy.Markings == nil {
		cfg.Policy.Markings = map[string]string{}
	}
	if cfg.Binding.ProfileID == "" {
		cfg.Binding.ProfileID = defaults.Binding.ProfileID
	}
	if cfg.Binding.ProofAlgorithm == "" {
		cfg.Binding.ProofAlgorithm = defaults.Binding.ProofAlgorithm
	}
	if cfg.Binding.KeyID == "" {
		cfg.Binding.KeyID = defaults.Binding.KeyID
	}
	if cfg.PIP.Channel == "" {
		cfg.PIP.Channel = defaults.PIP.Channel
	}
	if cfg.PIP.Purpose == "" {
		cfg.PIP.Purpose = defaults.PIP.Purpose
	}
	if cfg.PIP.DeviceTrust == 0 {
		cfg.PIP.DeviceTrust = defaults.PIP.DeviceTrust
	}
	if cfg.PIP.ClientIPHeader == "" {
		cfg.PIP.ClientIPHeader = defaults.PIP.ClientIPHeader
	}
	if cfg.PDP.DefaultClassification == "" {
		cfg.PDP.DefaultClassification = defaults.PDP.DefaultClassification
	}
	if len(cfg.PDP.ReadActions) == 0 {
		cfg.PDP.ReadActions = append([]string(nil), defaults.PDP.ReadActions...)
	}
	if len(cfg.PDP.WriteActions) == 0 {
		cfg.PDP.WriteActions = append([]string(nil), defaults.PDP.WriteActions...)
	}
	if len(cfg.PDP.BootstrapActions) == 0 {
		cfg.PDP.BootstrapActions = append([]string(nil), defaults.PDP.BootstrapActions...)
	}
	if len(cfg.PDP.AuditActions) == 0 {
		cfg.PDP.AuditActions = append([]string(nil), defaults.PDP.AuditActions...)
	}
	if cfg.PDP.RoleClassificationActions == nil {
		cfg.PDP.RoleClassificationActions = defaults.PDP.RoleClassificationActions
	}
	if len(cfg.PDP.SpectatorAgentHardeningFields) == 0 {
		cfg.PDP.SpectatorAgentHardeningFields = append([]string(nil), defaults.PDP.SpectatorAgentHardeningFields...)
	}
}
