package kms

import (
	"context"
	"testing"
)

func TestLocalClient_EncryptDecryptRoundtrip(t *testing.T) {
	client := NewLocalClient()

	cipher, err := client.Encrypt(context.Background(), "hello")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if cipher == "hello" {
		t.Fatalf("expected ciphertext to be different from plaintext")
	}

	plain, err := client.Decrypt(context.Background(), cipher)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if plain != "hello" {
		t.Fatalf("expected plaintext 'hello', got %q", plain)
	}
}

func TestLocalClient_DecryptNonPrefixed(t *testing.T) {
	client := NewLocalClient()
	plain, err := client.Decrypt(context.Background(), "plain-text")
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if plain != "plain-text" {
		t.Fatalf("expected passthrough for non-prefixed input")
	}
}

func TestLocalClient_DecryptInvalidBase64(t *testing.T) {
	client := NewLocalClient()
	_, err := client.Decrypt(context.Background(), "vault:v1:@@@")
	if err == nil {
		t.Fatalf("expected error for invalid base64")
	}
}

