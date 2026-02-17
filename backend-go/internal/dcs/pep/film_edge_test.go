package pep

import (
	"context"
	"errors"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type errorDecryptor struct{}

func (e *errorDecryptor) Decrypt(_ context.Context, _ string) (string, error) {
	return "", errors.New("decrypt failed")
}

func TestFilmApplier_MaskSensitiveField(t *testing.T) {
	rt := runtime.New("on", 3)
	dec := &fakeDecryptor{value: "120"}
	applier := NewFilmApplier(rt, dec)

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"title":        types.FieldActionAllow,
			"time_elapsed": types.FieldActionMaskAfterDecrypt,
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.Payload["time_elapsed"] != "1***" {
		t.Fatalf("expected masked time_elapsed, got %#v", result.Payload["time_elapsed"])
	}
	if len(result.Masked) != 1 || result.Masked[0] != "time_elapsed" {
		t.Fatalf("expected time_elapsed in masked list")
	}
	if dec.calls != 1 {
		t.Fatalf("expected one decrypt call, got %d", dec.calls)
	}
}

func TestFilmApplier_DenyDecision(t *testing.T) {
	rt := runtime.New("on", 3)
	dec := &fakeDecryptor{value: "120"}
	applier := NewFilmApplier(rt, dec)

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow:        false,
		FieldActions: map[string]types.FieldAction{},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(result.Payload) != 0 {
		t.Fatalf("expected empty payload on deny")
	}
	if len(result.Denied) != 2 {
		t.Fatalf("expected title and time_elapsed denied")
	}
	if dec.calls != 0 {
		t.Fatalf("decrypt should not be called on deny")
	}
}

func TestFilmApplier_DecryptNonInt(t *testing.T) {
	rt := runtime.New("on", 3)
	dec := &fakeDecryptor{value: "12s"}
	applier := NewFilmApplier(rt, dec)

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"time_elapsed": types.FieldActionDecrypt,
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.Payload["time_elapsed"] != "12s" {
		t.Fatalf("expected string time_elapsed when non-int, got %#v", result.Payload["time_elapsed"])
	}
}

func TestFilmApplier_DecryptError(t *testing.T) {
	rt := runtime.New("on", 3)
	applier := NewFilmApplier(rt, &errorDecryptor{})

	_, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"time_elapsed": types.FieldActionDecrypt,
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err == nil {
		t.Fatalf("expected decrypt error to propagate")
	}
}

