package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func main() {
	decision := types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"name": types.FieldActionMaskAfterDecrypt,
			"age":  types.FieldActionDecrypt,
		},
		Reason: "read_allowed",
	}

	// Manual implementation to debug
	fieldKeys := make([]string, 0, len(decision.FieldActions))
	for k := range decision.FieldActions {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)

	sortedActions := make(map[string]types.FieldAction, len(decision.FieldActions))
	for _, k := range fieldKeys {
		sortedActions[k] = decision.FieldActions[k]
	}

	payload := map[string]interface{}{
		"allow":         decision.Allow,
		"field_actions": sortedActions,
		"reason":        decision.Reason,
	}

	raw, _ := json.Marshal(payload)
	fmt.Println("JSON payload:", string(raw))

	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	fmt.Println("Go hash:", hash)

	// Also test with direct string values like Python
	pythonPayload := map[string]interface{}{
		"allow": true,
		"field_actions": map[string]string{
			"age":  "decrypt",
			"name": "mask_after_decrypt",
		},
		"reason": "read_allowed",
	}
	pythonRaw, _ := json.Marshal(pythonPayload)
	fmt.Println("\nPython-style JSON:", string(pythonRaw))

	pythonSum := sha256.Sum256(pythonRaw)
	pythonHash := hex.EncodeToString(pythonSum[:])
	fmt.Println("Python-style hash:", pythonHash)
}
