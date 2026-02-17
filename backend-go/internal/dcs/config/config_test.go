package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func TestLoad_ValidConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "dcs_config.json")

	configJSON := `{
  "pip": {
    "channel": "mobile",
    "purpose": "test_purpose",
    "device_trust": 0.9,
    "client_ip_header": "x-forwarded-for"
  },
  "pdp": {
    "default_classification": "SENSITIVE",
    "read_actions": ["test.read"],
    "write_actions": ["test.write"],
    "bootstrap_actions": ["bootstrap"],
    "audit_actions": ["audit.read"],
    "role_classification_actions": {
      "admin": {
        "PUBLIC": "allow"
      }
    },
    "spectator_agent_hardening_fields": ["test_field"]
  }
}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Load config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Assert PIP config
	if cfg.PIP.Channel != "mobile" {
		t.Errorf("Expected channel=mobile, got %s", cfg.PIP.Channel)
	}
	if cfg.PIP.Purpose != "test_purpose" {
		t.Errorf("Expected purpose=test_purpose, got %s", cfg.PIP.Purpose)
	}
	if cfg.PIP.DeviceTrust != 0.9 {
		t.Errorf("Expected device_trust=0.9, got %f", cfg.PIP.DeviceTrust)
	}
	if cfg.PIP.ClientIPHeader != "x-forwarded-for" {
		t.Errorf("Expected client_ip_header=x-forwarded-for, got %s", cfg.PIP.ClientIPHeader)
	}

	// Assert PDP config
	if cfg.PDP.DefaultClassification != types.ClassificationSensitive {
		t.Errorf("Expected default_classification=SENSITIVE, got %s", cfg.PDP.DefaultClassification)
	}
	if len(cfg.PDP.ReadActions) != 1 || cfg.PDP.ReadActions[0] != "test.read" {
		t.Errorf("Expected read_actions=[test.read], got %v", cfg.PDP.ReadActions)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
}

func TestLoad_EmptyPath(t *testing.T) {
	_, err := Load("")
	if err == nil {
		t.Fatal("Expected error for empty path")
	}
	if err.Error() != "DCS_CONFIG_PATH not specified" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(configPath, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
}

func TestDefaults_PIP(t *testing.T) {
	cfg := Defaults()

	// Check PIP defaults match hardcoded values
	if cfg.PIP.Channel != "web" {
		t.Errorf("Expected default channel=web, got %s", cfg.PIP.Channel)
	}
	if cfg.PIP.Purpose != "cinema_ops" {
		t.Errorf("Expected default purpose=cinema_ops, got %s", cfg.PIP.Purpose)
	}
	if cfg.PIP.DeviceTrust != 0.8 {
		t.Errorf("Expected default device_trust=0.8, got %f", cfg.PIP.DeviceTrust)
	}
	if cfg.PIP.ClientIPHeader != "x-real-ip" {
		t.Errorf("Expected default client_ip_header=x-real-ip, got %s", cfg.PIP.ClientIPHeader)
	}
}

func TestDefaults_PDP(t *testing.T) {
	cfg := Defaults()

	// Check PDP defaults
	if cfg.PDP.DefaultClassification != types.ClassificationInternal {
		t.Errorf("Expected default_classification=INTERNAL, got %s", cfg.PDP.DefaultClassification)
	}

	// Check read actions include expected values
	expectedReadActions := []string{"film.read", "hall.read", "spectator.read"}
	if len(cfg.PDP.ReadActions) != len(expectedReadActions) {
		t.Errorf("Expected %d read actions, got %d", len(expectedReadActions), len(cfg.PDP.ReadActions))
	}

	// Check write actions (search.spectator is write-restricted: agent/admin only)
	expectedWriteActions := []string{"film.create", "hall.create", "spectator.create", "film.update_time", "search.spectator"}
	if len(cfg.PDP.WriteActions) != len(expectedWriteActions) {
		t.Errorf("Expected %d write actions, got %d", len(expectedWriteActions), len(cfg.PDP.WriteActions))
	}

	// Check role classification actions
	if _, ok := cfg.PDP.RoleClassificationActions["admin"]; !ok {
		t.Error("Expected admin role in RoleClassificationActions")
	}
	if _, ok := cfg.PDP.RoleClassificationActions["agent"]; !ok {
		t.Error("Expected agent role in RoleClassificationActions")
	}
	if _, ok := cfg.PDP.RoleClassificationActions["developer"]; !ok {
		t.Error("Expected developer role in RoleClassificationActions")
	}

	// Check spectator hardening
	expectedHardening := []string{"name", "external_id"}
	if len(cfg.PDP.SpectatorAgentHardeningFields) != len(expectedHardening) {
		t.Errorf("Expected %d hardening fields, got %d", len(expectedHardening), len(cfg.PDP.SpectatorAgentHardeningFields))
	}
}

func TestDefaults_RoleClassificationMatrix(t *testing.T) {
	cfg := Defaults()

	// Test admin can decrypt everything
	adminActions := cfg.PDP.RoleClassificationActions["admin"]
	if adminActions["SENSITIVE"] != "decrypt" {
		t.Errorf("Expected admin SENSITIVE=decrypt, got %s", adminActions["SENSITIVE"])
	}
	if adminActions["PII"] != "decrypt" {
		t.Errorf("Expected admin PII=decrypt, got %s", adminActions["PII"])
	}

	// Test agent can decrypt SENSITIVE but mask PII
	agentActions := cfg.PDP.RoleClassificationActions["agent"]
	if agentActions["SENSITIVE"] != "decrypt" {
		t.Errorf("Expected agent SENSITIVE=decrypt, got %s", agentActions["SENSITIVE"])
	}
	if agentActions["PII"] != "mask_after_decrypt" {
		t.Errorf("Expected agent PII=mask_after_decrypt, got %s", agentActions["PII"])
	}

	// Test developer masks everything except PUBLIC
	devActions := cfg.PDP.RoleClassificationActions["developer"]
	if devActions["PUBLIC"] != "allow" {
		t.Errorf("Expected developer PUBLIC=allow, got %s", devActions["PUBLIC"])
	}
	if devActions["INTERNAL"] != "mask_after_decrypt" {
		t.Errorf("Expected developer INTERNAL=mask_after_decrypt, got %s", devActions["INTERNAL"])
	}
}
