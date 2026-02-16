package pep

import (
	"strconv"
	"strings"
)

// MaskString masks a string value.
// Python parity: data_pep.py:11-15
// Returns first character + "***"
func MaskString(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 2 {
		return strings.Repeat("*", len(s))
	}
	return s[:1] + "***"
}

// MaskAge masks an age value.
// Python parity: data_pep.py:25-32
// Returns "-18" for minors, "+18" for adults
func MaskAge(age int) string {
	if age < 18 {
		return "-18"
	}
	return "+18"
}

// ApplyMask applies field-specific masking based on field name.
// Dispatches to MaskString, MaskAge, or MaskUUID depending on field.
// Python parity: data_pep.py:111-116 (mask based on field type)
func ApplyMask(field string, plaintext string) string {
	switch {
	case field == "age":
		age, err := strconv.Atoi(plaintext)
		if err != nil {
			return "***"
		}
		return MaskAge(age)
	case strings.HasSuffix(field, "_id") && field != "external_id":
		// Mask UUID fields (owner_user_id, current_film_id, hall_id, etc.)
		// external_id is a ticket string (like "ABC123"), not a UUID
		return MaskUUID(plaintext)
	default:
		return MaskString(plaintext)
	}
}
