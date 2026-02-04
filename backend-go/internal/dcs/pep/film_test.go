package pep

import (
	"context"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type fakeDecryptor struct {
	value string
	calls int
}

func (f *fakeDecryptor) Decrypt(_ context.Context, _ string) (string, error) {
	f.calls++
	return f.value, nil
}

func TestFilmApplier_DecryptSensitiveField(t *testing.T) {
	rt := runtime.New("on", 3)
	dec := &fakeDecryptor{value: "120"}
	applier := NewFilmApplier(rt, dec)

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow: true,
		FieldActions: map[string]types.FieldAction{
			"title":        types.FieldActionAllow,
			"time_elapsed": types.FieldActionDecrypt,
		},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.Payload["time_elapsed"] != 120 {
		t.Fatalf("expected int decrypted time_elapsed, got %#v", result.Payload["time_elapsed"])
	}
	if dec.calls != 1 {
		t.Fatalf("expected one decrypt call, got %d", dec.calls)
	}
}

func TestFilmApplier_DcsOffReturnsCiphertext(t *testing.T) {
	rt := runtime.New("off", 3)
	dec := &fakeDecryptor{value: "120"}
	applier := NewFilmApplier(rt, dec)

	result, err := applier.Apply(context.Background(), types.Decision{
		Allow:        true,
		FieldActions: map[string]types.FieldAction{},
	}, FilmRow{
		Title:         "Interstellar",
		TimeElapsedCT: "vault:v1:abc",
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.Payload["time_elapsed"] != "vault:v1:abc" {
		t.Fatalf("expected ciphertext passthrough in dcs off mode")
	}
	if dec.calls != 0 {
		t.Fatalf("decrypt should not be called in dcs off mode")
	}
}
