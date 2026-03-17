package spif

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type Policy struct {
	PolicyID            string
	PolicyVersion       string
	ClassificationOrder []service.Classification
	AllowedCategories   []string
	Markings            map[string]string
}

type Provider interface {
	Current(ctx context.Context) (Policy, error)
}

type StaticProvider struct {
	policy Policy
}

func NewStaticProvider(cfg config.PolicyConfig) *StaticProvider {
	return &StaticProvider{policy: Policy{
		PolicyID:            cfg.PolicyID,
		PolicyVersion:       cfg.PolicyVersion,
		ClassificationOrder: append([]service.Classification(nil), cfg.ClassificationOrder...),
		AllowedCategories:   append([]string(nil), cfg.AllowedCategories...),
		Markings:            cloneMap(cfg.Markings),
	}}
}

func (p *StaticProvider) Current(ctx context.Context) (Policy, error) {
	_ = ctx
	return Policy{
		PolicyID:            p.policy.PolicyID,
		PolicyVersion:       p.policy.PolicyVersion,
		ClassificationOrder: append([]service.Classification(nil), p.policy.ClassificationOrder...),
		AllowedCategories:   append([]string(nil), p.policy.AllowedCategories...),
		Markings:            cloneMap(p.policy.Markings),
	}, nil
}

func cloneMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(values))
	for k, v := range values {
		cloned[k] = v
	}
	return cloned
}
