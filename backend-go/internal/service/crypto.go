package service

import "context"

type CryptoProvider interface {
	Encrypt(ctx context.Context, plaintext string) (string, error)
	Decrypt(ctx context.Context, ciphertext string) (string, error)
	GetPepper(ctx context.Context, path string) ([]byte, error)
}
