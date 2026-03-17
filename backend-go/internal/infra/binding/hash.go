package binding

import (
	"crypto/sha256"
	"encoding/hex"
)

func SHA256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func PayloadHash(payload any) (string, error) {
	raw, err := CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return SHA256Hex(raw), nil
}

func LabelHash(label any) (string, error) {
	raw, err := CanonicalJSON(label)
	if err != nil {
		return "", err
	}
	return SHA256Hex(raw), nil
}
