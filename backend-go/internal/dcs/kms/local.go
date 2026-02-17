package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
)

const prefix = "vault:v1:"

type LocalClient struct{}

func NewLocalClient() *LocalClient {
	return &LocalClient{}
}

func (c *LocalClient) Encrypt(_ context.Context, plaintext string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	return prefix + encoded, nil
}

func (c *LocalClient) Decrypt(_ context.Context, ciphertext string) (string, error) {
	raw := strings.TrimSpace(ciphertext)
	if !strings.HasPrefix(raw, prefix) {
		return raw, nil
	}
	payload := strings.TrimPrefix(raw, prefix)
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	return string(decoded), nil
}

// GetPepper returns a static pepper for local development
// In production, this should retrieve from Vault KV
func (c *LocalClient) GetPepper(_ context.Context, _ string) ([]byte, error) {
	// Static pepper for local/dev mode (NOT SECURE - for development only)
	return []byte("local-dev-pepper-not-secure"), nil
}
