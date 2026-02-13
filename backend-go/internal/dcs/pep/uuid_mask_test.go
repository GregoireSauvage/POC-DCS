package pep

import "testing"

func TestMaskUUID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard UUID",
			input:    "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e…",
		},
		{
			name:     "different UUID",
			input:    "123e4567-e89b-12d3-a456-426614174000",
			expected: "123e…",
		},
		{
			name:     "short string (8 chars)",
			input:    "12345678",
			expected: "****",
		},
		{
			name:     "short string (less than 8)",
			input:    "1234",
			expected: "****",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "****",
		},
		{
			name:     "exactly 9 chars",
			input:    "123456789",
			expected: "1234…",
		},
		{
			name:     "invalid UUID format but long enough",
			input:    "not-a-uuid-but-long",
			expected: "not-…",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskUUID(tt.input)
			if got != tt.expected {
				t.Errorf("MaskUUID(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestMaskUUID_PythonParity verifies the output matches Python exactly
func TestMaskUUID_PythonParity(t *testing.T) {
	// Python: mask_uuid("550e8400-e29b-41d4-a716-446655440000") == "550e…"
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	expected := "550e…"
	got := MaskUUID(uuid)
	if got != expected {
		t.Errorf("Python parity failed: got %q, want %q", got, expected)
	}
}
