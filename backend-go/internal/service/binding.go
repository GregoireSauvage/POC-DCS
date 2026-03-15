package service

import (
	"context"
	"time"
)

type BindingRecord struct {
	ProfileID      string
	KeyID          string
	PayloadHash    string
	LabelHash      string
	Proof          string
	ProofAlgorithm string
	CreatedAt      time.Time
}

type BindingVerifier interface {
	Verify(ctx context.Context, payload any, label Label, binding BindingRecord) error
}
