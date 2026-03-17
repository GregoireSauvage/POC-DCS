package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)

func NormalizeExternalID(externalID string) string {
	return strings.ToUpper(strings.TrimSpace(externalID))
}

func ComputeHMACLookup(pepper []byte, normalizedValue string) []byte {
	h := hmac.New(sha256.New, pepper)
	_, _ = h.Write([]byte(normalizedValue))
	return h.Sum(nil)
}
