package pip

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
)

type ClassificationStore interface {
	GetByResourceType(ctx context.Context, resourceType string) (map[string]types.Classification, error)
}

type Config struct {
	Env            string
	Channel        string
	Purpose        string
	DeviceTrust    float64
	ClientIPHeader string
}

type Input struct {
	Principal    types.Principal
	Action       string
	ResourceType string
	ResourceID   string
	OwnerID      string
	Labels       []string
	Request      types.RequestContext
	CryptoMeta   map[string]map[string]string
}

type Provider struct {
	runtime *runtime.Settings
	cache   *cache.Manager
	store   ClassificationStore
	cfg     Config
}

func NewProvider(rt *runtime.Settings, cm *cache.Manager, store ClassificationStore, cfg Config) *Provider {
	return &Provider{
		runtime: rt,
		cache:   cm,
		store:   store,
		cfg:     cfg,
	}
}

func (p *Provider) Build(ctx context.Context, in Input) (types.PolicyInput, error) {
	defer perf.Span(ctx, "pip_ms")()

	fields := map[string]types.FieldMeta{}
	if p.runtime.DcsEnabled() {
		clsMap, err := p.getClassificationMap(ctx, in.ResourceType)
		if err != nil {
			return types.PolicyInput{}, err
		}
		for fieldName, cls := range clsMap {
			meta := types.FieldMeta{Classification: cls}
			if crypto, ok := in.CryptoMeta[fieldName]; ok {
				meta.Crypto = crypto
			}
			fields[fieldName] = meta
		}
	}

	reqCtx := in.Request
	if reqCtx.Channel == "" {
		reqCtx.Channel = p.cfg.Channel
	}
	if reqCtx.Purpose == "" {
		reqCtx.Purpose = p.cfg.Purpose
	}
	if reqCtx.Env == "" {
		reqCtx.Env = p.cfg.Env
	}
	if reqCtx.DeviceTrust == 0 {
		reqCtx.DeviceTrust = p.cfg.DeviceTrust
	}

	return types.PolicyInput{
		Principal: in.Principal,
		Action:    in.Action,
		Resource: types.Resource{
			Type:     in.ResourceType,
			ID:       in.ResourceID,
			OwnerID:  in.OwnerID,
			TenantID: in.Principal.TenantID,
			Labels:   in.Labels,
			Fields:   fields,
		},
		Context: reqCtx,
	}, nil
}

func (p *Provider) getClassificationMap(ctx context.Context, resourceType string) (map[string]types.Classification, error) {
	if p.cache.LevelEnabled(1) {
		if cached, ok := p.cache.Classification.Get(resourceType); ok {
			return cached, nil
		}
	}

	rows, err := p.store.GetByResourceType(ctx, resourceType)
	if err != nil {
		return nil, err
	}
	if p.cache.LevelEnabled(1) {
		p.cache.Classification.Set(resourceType, rows, 0)
	}
	return rows, nil
}
