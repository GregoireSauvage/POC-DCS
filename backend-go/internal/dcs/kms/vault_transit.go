package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	vault "github.com/hashicorp/vault/api"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
)

// VaultTransitClient implements KMS using HashiCorp Vault Transit
type VaultTransitClient struct {
	client     *vault.Client
	transitKey string
	cache      *cache.Manager
	logger     *slog.Logger
}

// NewVaultTransitClient creates a new Vault Transit KMS client
func NewVaultTransitClient(addr, token, transitKey string, cacheManager *cache.Manager, logger *slog.Logger) (*VaultTransitClient, error) {
	config := vault.DefaultConfig()
	config.Address = addr

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(token)

	// Test connection by checking seal status
	ctx := context.Background()
	sealStatus, err := client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check vault status: %w", err)
	}

	if sealStatus.Sealed {
		return nil, fmt.Errorf("vault is sealed")
	}

	logger.Info("vault transit client connected",
		slog.String("addr", addr),
		slog.String("transit_key", transitKey),
		slog.Bool("sealed", sealStatus.Sealed),
	)

	return &VaultTransitClient{
		client:     client,
		transitKey: transitKey,
		cache:      cacheManager,
		logger:     logger,
	}, nil
}

// Encrypt encrypts plaintext using Vault Transit
func (v *VaultTransitClient) Encrypt(ctx context.Context, plaintext string) (string, error) {
	// Base64 encode the plaintext (Vault Transit requirement)
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))

	payload := map[string]interface{}{
		"plaintext": encoded,
	}

	path := fmt.Sprintf("/v1/transit/encrypt/%s", v.transitKey)
	secret, err := v.client.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		return "", fmt.Errorf("vault encrypt failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault encrypt returned nil data")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("vault encrypt response missing ciphertext")
	}

	v.logger.Debug("vault encrypt successful",
		slog.Int("plaintext_len", len(plaintext)),
		slog.Int("ciphertext_len", len(ciphertext)),
	)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using Vault Transit with cache
func (v *VaultTransitClient) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	// Check cache first (level 3)
	if v.cache.LevelEnabled(3) {
		if cached, found := v.cache.KMS.Get(ciphertext); found {
			v.logger.Debug("vault decrypt cache hit", slog.String("ciphertext_prefix", ciphertext[:20]))
			return cached, nil
		}
	}

	// Call Vault Transit decrypt
	payload := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	path := fmt.Sprintf("/v1/transit/decrypt/%s", v.transitKey)
	secret, err := v.client.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		return "", fmt.Errorf("vault decrypt failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault decrypt returned nil data")
	}

	encoded, ok := secret.Data["plaintext"].(string)
	if !ok {
		return "", fmt.Errorf("vault decrypt response missing plaintext")
	}

	// Base64 decode the result
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode plaintext: %w", err)
	}

	plaintext := string(decoded)

	// Cache the result (level 3) - use default TTL (0)
	if v.cache.LevelEnabled(3) {
		v.cache.KMS.Set(ciphertext, plaintext, 0)
	}

	v.logger.Debug("vault decrypt successful",
		slog.String("ciphertext_prefix", ciphertext[:20]),
		slog.Int("plaintext_len", len(plaintext)),
	)

	return plaintext, nil
}

// GetPepper fetches the pepper secret from Vault KV v2
func (v *VaultTransitClient) GetPepper(ctx context.Context, path string) ([]byte, error) {
	// Check cache first (level 1)
	if v.cache.LevelEnabled(1) {
		if cached, found := v.cache.Pepper.Get("pepper"); found {
			v.logger.Debug("pepper cache hit")
			return cached, nil
		}
	}

	// Vault KV v2 path format: /v1/{mount}/data/{path}
	// Assuming default mount "secret"
	kvPath := fmt.Sprintf("/v1/secret/data/%s", path)

	secret, err := v.client.Logical().ReadWithContext(ctx, kvPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pepper from vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("pepper secret not found at %s", path)
	}

	// KV v2 stores data under "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected pepper secret format")
	}

	pepperStr, ok := data["pepper"].(string)
	if !ok {
		return nil, fmt.Errorf("pepper field not found in secret")
	}

	pepper := []byte(pepperStr)

	// Cache the pepper (level 1) - use default TTL (0)
	if v.cache.LevelEnabled(1) {
		v.cache.Pepper.Set("pepper", pepper, 0)
	}

	v.logger.Info("pepper loaded from vault",
		slog.String("path", path),
		slog.Int("pepper_len", len(pepper)),
	)

	return pepper, nil
}
