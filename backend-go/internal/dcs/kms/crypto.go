package kms

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)

// NormalizeExternalID normalizes an external ID for lookup computation.
// Matches Python implementation: external_id.strip().upper()
//
// The normalization ensures case-insensitive and whitespace-insensitive lookups:
//   - Strips leading and trailing whitespace (tabs, spaces, newlines)
//   - Converts to uppercase
//
// Example:
//
//	NormalizeExternalID("  abc123  ") // Returns "ABC123"
//	NormalizeExternalID("Café")       // Returns "CAFÉ"
func NormalizeExternalID(externalID string) string {
	return strings.ToUpper(strings.TrimSpace(externalID))
}

// ComputeHMACLookup computes HMAC-SHA256 for searchable encryption lookup.
// Returns 32-byte digest matching Python's hmac.new(pepper, value, sha256).digest()
//
// This enables searchable encryption: the HMAC digest is stored in the database
// (external_id_lookup BYTEA column) to allow efficient queries without exposing
// the plaintext external_id. The actual external_id is stored encrypted separately.
//
// Parameters:
//   - pepper: Secret key from Vault KV store (retrieved via GetPepper)
//   - normalizedValue: Pre-normalized value (use NormalizeExternalID first)
//
// Returns:
//   - 32-byte HMAC-SHA256 digest for database storage
//
// Example:
//
//	pepper := []byte("secret-from-vault")
//	normalized := NormalizeExternalID("  ABC-123  ") // "ABC-123"
//	lookup := ComputeHMACLookup(pepper, normalized)  // 32 bytes for BYTEA
func ComputeHMACLookup(pepper []byte, normalizedValue string) []byte {
	h := hmac.New(sha256.New, pepper)
	h.Write([]byte(normalizedValue))
	return h.Sum(nil)
}
