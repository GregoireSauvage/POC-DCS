package pep

import (
	"context"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

func TestFilmApplier_TitleMaskAndTimeDeny(t *testing.T) {
	rt := runtime.New("on", 3)
	applier := NewFilmApplier(rt, &fakeDecryptor{value: "120"})

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"title":        types.FieldActionMaskAfterDecrypt,
			"time_elapsed": types.FieldActionDeny,
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if result.Payload["title"] != "I***" {
		t.Fatalf("expected masked title, got %#v", result.Payload["title"])
	}
	if result.Payload["time_elapsed"] != nil {
		t.Fatalf("expected denied time_elapsed to be nil")
	}
	if len(result.Denied) != 1 || result.Denied[0] != "time_elapsed" {
		t.Fatalf("expected time_elapsed in denied list")
	}
}

func TestFilmApplier_TitleDenyAndTimeDefaultPassthrough(t *testing.T) {
	rt := runtime.New("on", 3)
	applier := NewFilmApplier(rt, &fakeDecryptor{value: "120"})

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"title":        types.FieldActionDeny,
			"time_elapsed": "",
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if result.Payload["title"] != nil {
		t.Fatalf("expected denied title to be nil")
	}
	if result.Payload["time_elapsed"] != "vault:v1:abc" {
		t.Fatalf("expected passthrough ciphertext in default branch")
	}
}

func TestFilmApplier_TitleDefaultAllowFallback(t *testing.T) {
	rt := runtime.New("on", 3)
	applier := NewFilmApplier(rt, &fakeDecryptor{value: "120"})

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"title":        "",
			"time_elapsed": types.FieldActionDecrypt,
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if result.Payload["title"] != "Interstellar" {
		t.Fatalf("expected title fallback to clear value, got %#v", result.Payload["title"])
	}
}

func TestFilmApplier_MaskActionDecryptError(t *testing.T) {
	rt := runtime.New("on", 3)
	applier := NewFilmApplier(rt, &errorDecryptor{})

	_, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"time_elapsed": types.FieldActionMaskAfterDecrypt,
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err == nil {
		t.Fatalf("expected decrypt error for mask action")
	}
}

func TestMaskString_ShortValues(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "**"},
		{"a", "**"},
		{"ab", "**"},
		{"abc", "a***"},
	}

	for _, tc := range cases {
		if got := maskString(tc.in); got != tc.want {
			t.Fatalf("maskString(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}
