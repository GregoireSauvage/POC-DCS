package pep

// MaskUUID masks a UUID string for developer role
// Python parity: backend/app/dcs/pep/data_pep.py:18-22
//
// Example:
//   Input:  "550e8400-e29b-41d4-a716-446655440000"
//   Output: "550e…"
func MaskUUID(id string) string {
	if len(id) <= 8 {
		return "****"
	}
	// First 4 chars + ellipsis (UTF-8 character "…", not "...")
	return id[:4] + "…"
}
