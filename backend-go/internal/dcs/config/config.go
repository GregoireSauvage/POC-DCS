package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

// DCSConfig represents the full DCS configuration loaded from dcs_config.json
type DCSConfig struct {
	PIP PIPConfig `json:"pip"`
	PDP PDPConfig `json:"pdp"`
}

// PIPConfig represents the PIP section of the DCS config
type PIPConfig struct {
	Channel        string  `json:"channel"`
	Purpose        string  `json:"purpose"`
	DeviceTrust    float64 `json:"device_trust"`
	ClientIPHeader string  `json:"client_ip_header"`
}

// PDPConfig represents the PDP section of the DCS config
type PDPConfig struct {
	DefaultClassification          types.Classification            `json:"default_classification"`
	ReadActions                    []string                        `json:"read_actions"`
	WriteActions                   []string                        `json:"write_actions"`
	BootstrapActions               []string                        `json:"bootstrap_actions"`
	AuditActions                   []string                        `json:"audit_actions"`
	RoleClassificationActions      map[string]map[string]string    `json:"role_classification_actions"`
	SpectatorAgentHardeningFields  []string                        `json:"spectator_agent_hardening_fields"`
}

// Load reads and parses the DCS config file from the given path
func Load(path string) (*DCSConfig, error) {
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

	return &cfg, nil
}

// Defaults returns default config values (fallback when config file not available)
func Defaults() *DCSConfig {
	return &DCSConfig{
		PIP: PIPConfig{
			Channel:        "web",
			Purpose:        "cinema_ops",
			DeviceTrust:    0.8,
			ClientIPHeader: "x-real-ip",
		},
		PDP: PDPConfig{
			DefaultClassification: types.ClassificationInternal,
			ReadActions:          []string{"film.read", "hall.read", "spectator.read"},
			WriteActions:         []string{"film.create", "hall.create", "spectator.create", "film.update_time", "search.spectator"},
			BootstrapActions:     []string{"bootstrap"},
			AuditActions:         []string{"audit.read", "perf.read"},
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
}
