package pep

import (
	"context"
	"strconv"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type Decryptor interface {
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

type FilmRow struct {
	Title         string
	TimeElapsedCT string
}

type ApplyResult struct {
	Payload   map[string]interface{}
	Decrypted []string
	Masked    []string
	Denied    []string
}

type FilmApplier struct {
	runtime *runtime.Settings
	kms     Decryptor
}

func NewFilmApplier(rt *runtime.Settings, kms Decryptor) *FilmApplier {
	return &FilmApplier{
		runtime: rt,
		kms:     kms,
	}
}

func (a *FilmApplier) Apply(ctx context.Context, decision types.Decision, row FilmRow) (ApplyResult, error) {
	if !decision.Allow {
		return ApplyResult{
			Payload: map[string]interface{}{},
			Denied:  []string{"title", "time_elapsed"},
		}, nil
	}

	out := map[string]interface{}{}
	if !a.runtime.DcsEnabled() {
		out["title"] = row.Title
		out["time_elapsed"] = row.TimeElapsedCT
		return ApplyResult{Payload: out}, nil
	}

	if action, ok := decision.FieldActions["title"]; ok {
		switch action {
		case types.FieldActionAllow:
			out["title"] = row.Title
		case types.FieldActionMaskAfterDecrypt:
			out["title"] = maskString(row.Title)
		case types.FieldActionDeny:
			out["title"] = nil
		default:
			out["title"] = row.Title
		}
	}

	action := decision.FieldActions["time_elapsed"]
	switch action {
	case types.FieldActionDecrypt:
		plain, err := a.kms.Decrypt(ctx, row.TimeElapsedCT)
		if err != nil {
			return ApplyResult{}, err
		}
		if asInt, err := strconv.Atoi(plain); err == nil {
			out["time_elapsed"] = asInt
		} else {
			out["time_elapsed"] = plain
		}
		return ApplyResult{Payload: out, Decrypted: []string{"time_elapsed"}}, nil
	case types.FieldActionMaskAfterDecrypt:
		plain, err := a.kms.Decrypt(ctx, row.TimeElapsedCT)
		if err != nil {
			return ApplyResult{}, err
		}
		out["time_elapsed"] = maskString(plain)
		return ApplyResult{Payload: out, Masked: []string{"time_elapsed"}}, nil
	case types.FieldActionDeny:
		out["time_elapsed"] = nil
		return ApplyResult{Payload: out, Denied: []string{"time_elapsed"}}, nil
	default:
		out["time_elapsed"] = row.TimeElapsedCT
		return ApplyResult{Payload: out}, nil
	}
}

func maskString(v string) string {
	if len(v) <= 2 {
		return "**"
	}
	return v[:1] + "***"
}
