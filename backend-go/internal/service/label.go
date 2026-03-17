package service

import (
	"context"
	"time"
)

type Label struct {
	PolicyID       string
	PolicyVersion  string
	Classification Classification
	Categories     []string
	Originator     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type ResourceLabel = Label

type LabelIssuer interface {
	Issue(ctx context.Context, access AccessContext, resource Resource) (Label, error)
}
