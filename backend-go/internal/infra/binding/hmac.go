package binding

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func HMACProof(key []byte, payloadHash string, labelHash string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(payloadHash))
	h.Write([]byte(":"))
	h.Write([]byte(labelHash))
	return hex.EncodeToString(h.Sum(nil))
}

func VerifyHMACProof(key []byte, payloadHash string, labelHash string, proof string) bool {
	expected := HMACProof(key, payloadHash, labelHash)
	return hmac.Equal([]byte(expected), []byte(proof))
}
