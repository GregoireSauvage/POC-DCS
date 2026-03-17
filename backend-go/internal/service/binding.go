package service

import (
	"context"
	"errors"
	"time"
)

var (
	ErrBindingMissing   = errors.New("binding missing")
	ErrBindingInvalid   = errors.New("binding invalid")
	ErrBindingCorrupted = errors.New("binding corrupted")
)

type BindingRecord struct {
	ProfileID      string
	KeyID          string
	PayloadHash    string
	LabelHash      string
	Proof          string
	ProofAlgorithm string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ResourceBinding struct {
	TenantID     string
	ResourceType string
	ResourceID   string
	Label        Label
	Binding      BindingRecord
}

type BindingIssuer interface {
	Create(ctx context.Context, payload any, label Label) (BindingRecord, error)
}

type BindingVerifier interface {
	Verify(ctx context.Context, payload any, label Label, binding BindingRecord) error
}

type BindingStore interface {
	Get(ctx context.Context, tenantID, resourceType, resourceID string) (ResourceBinding, error)
	GetMany(ctx context.Context, tenantID, resourceType string, resourceIDs []string) (map[string]ResourceBinding, error)
	Upsert(ctx context.Context, binding ResourceBinding) error
}
