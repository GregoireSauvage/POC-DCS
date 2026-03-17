package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDCSConfig_WithPolicyBlock(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "dcs.json")
	content := `{
  "policy": {
    "policy_id": "cinema-default",
    "policy_version": "v2",
    "classification_order": ["PUBLIC", "INTERNAL", "SENSITIVE", "PII"],
    "allowed_categories": [],
    "markings": {}
  },
  "pip": {"channel": "web", "purpose": "cinema_ops", "device_trust": 0.8, "client_ip_header": "x-real-ip"},
  "pdp": {"default_classification": "INTERNAL", "read_actions": ["film.read"], "write_actions": ["film.create"], "bootstrap_actions": ["bootstrap"], "audit_actions": ["audit.read"], "role_classification_actions": {"admin": {"PUBLIC": "allow"}}, "spectator_agent_hardening_fields": []}
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadDCSConfig(path)
	if err != nil {
		t.Fatalf("LoadDCSConfig: %v", err)
	}
	if cfg.Policy.PolicyVersion != "v2" {
		t.Fatalf("expected policy version v2, got %q", cfg.Policy.PolicyVersion)
	}
}
