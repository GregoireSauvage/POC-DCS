package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	vault "github.com/hashicorp/vault/api"

	"github.com/neoweyss/poc-dcs/backend-go/internal/infra/cache"
)

type VaultTransitClient struct {
	client     *vault.Client
	transitKey string
	cache      *cache.Manager
	logger     *slog.Logger
}

func NewVaultTransitClient(addr, token, transitKey string, cacheManager *cache.Manager, logger *slog.Logger) (*VaultTransitClient, error) {
	config := vault.DefaultConfig()
	config.Address = addr

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(token)

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

	return &VaultTransitClient{client: client, transitKey: transitKey, cache: cacheManager, logger: logger}, nil
}

func (v *VaultTransitClient) Encrypt(ctx context.Context, plaintext string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	payload := map[string]interface{}{"plaintext": encoded}
	path := fmt.Sprintf("transit/encrypt/%s", v.transitKey)
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
	v.logger.Debug("vault encrypt successful", slog.Int("plaintext_len", len(plaintext)), slog.Int("ciphertext_len", len(ciphertext)))
	return ciphertext, nil
}

func (v *VaultTransitClient) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	if v.cache != nil && v.cache.LevelEnabled(3) {
		if cached, found := v.cache.KMS.Get(ciphertext); found {
			v.logger.Debug("vault decrypt cache hit", slog.String("ciphertext_prefix", ciphertext[:20]))
			return cached, nil
		}
	}

	payload := map[string]interface{}{"ciphertext": ciphertext}
	path := fmt.Sprintf("transit/decrypt/%s", v.transitKey)
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
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode plaintext: %w", err)
	}
	plaintext := string(decoded)
	if v.cache != nil && v.cache.LevelEnabled(3) {
		v.cache.KMS.Set(ciphertext, plaintext, 0)
	}
	v.logger.Debug("vault decrypt successful", slog.String("ciphertext_prefix", ciphertext[:20]), slog.Int("plaintext_len", len(plaintext)))
	return plaintext, nil
}

func (v *VaultTransitClient) GetPepper(ctx context.Context, path string) ([]byte, error) {
	if v.cache != nil && v.cache.LevelEnabled(1) {
		if cached, found := v.cache.Pepper.Get("pepper"); found {
			v.logger.Debug("pepper cache hit")
			return cached, nil
		}
	}

	clean := strings.Trim(path, "/")
	switch {
	case strings.HasPrefix(clean, "secret/data/"):
	case strings.HasPrefix(clean, "secret/"):
		clean = strings.TrimPrefix(clean, "secret/")
		clean = fmt.Sprintf("secret/data/%s", clean)
	default:
		clean = fmt.Sprintf("secret/data/%s", clean)
	}

	secret, err := v.client.Logical().ReadWithContext(ctx, clean)
	if err != nil {
		return nil, fmt.Errorf("failed to read pepper from vault: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("pepper secret not found at %s", path)
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected pepper secret format")
	}
	pepperStr, ok := data["pepper"].(string)
	if !ok {
		return nil, fmt.Errorf("pepper field not found in secret")
	}
	pepper := []byte(pepperStr)
	if v.cache != nil && v.cache.LevelEnabled(1) {
		v.cache.Pepper.Set("pepper", pepper, 0)
	}
	v.logger.Info("pepper loaded from vault", slog.String("path", path), slog.Int("pepper_len", len(pepper)))
	return pepper, nil
}
