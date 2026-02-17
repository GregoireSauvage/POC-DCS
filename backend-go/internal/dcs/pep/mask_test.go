package pep

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal string", "John Doe", "J***"},
		{"short string", "AB", "**"},
		{"single char", "A", "*"},
		{"empty string", "", ""},
		{"unicode", "Café", "C***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskAge(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{"minor", 15, "-18"},
		{"exactly 18", 18, "+18"},
		{"adult", 25, "+18"},
		{"elderly", 80, "+18"},
		{"zero", 0, "-18"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskAge(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestApplyMask_FieldSpecific(t *testing.T) {
	tests := []struct {
		name      string
		field     string
		plaintext string
		expected  string
	}{
		{"age field", "age", "25", "+18"},
		{"age field minor", "age", "15", "-18"},
		{"age field invalid", "age", "invalid", "***"},
		{"external_id field", "external_id", "ABC123", "A***"},                         // Ticket string, not UUID
		{"hall_id field", "hall_id", "550e8400-e29b-41d4-a716-446655440000", "550e…"}, // UUID field
		{"name field", "name", "John Doe", "J***"},
		{"generic field", "other", "value", "v***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ApplyMask(tt.field, tt.plaintext)
			assert.Equal(t, tt.expected, result)
		})
	}
}
