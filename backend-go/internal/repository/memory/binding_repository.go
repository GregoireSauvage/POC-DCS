package memory

import (
	"context"
	"sync"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type BindingRepository struct {
	mu       sync.RWMutex
	bindings map[string]service.ResourceBinding
}

func NewBindingRepository() *BindingRepository {
	return &BindingRepository{
		bindings: make(map[string]service.ResourceBinding),
	}
}

func (r *BindingRepository) Get(_ context.Context, tenantID, resourceType, resourceID string) (service.ResourceBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	binding, ok := r.bindings[bindingKey(tenantID, resourceType, resourceID)]
	if !ok {
		return service.ResourceBinding{}, service.ErrBindingMissing
	}
	return binding, nil
}

func (r *BindingRepository) GetMany(_ context.Context, tenantID, resourceType string, resourceIDs []string) (map[string]service.ResourceBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make(map[string]service.ResourceBinding, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		if binding, ok := r.bindings[bindingKey(tenantID, resourceType, resourceID)]; ok {
			results[resourceID] = binding
		}
	}
	return results, nil
}

func (r *BindingRepository) Upsert(_ context.Context, binding service.ResourceBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.bindings[bindingKey(binding.TenantID, binding.ResourceType, binding.ResourceID)] = binding
	return nil
}

func bindingKey(tenantID, resourceType, resourceID string) string {
	return tenantID + "|" + resourceType + "|" + resourceID
}

var _ service.BindingStore = (*BindingRepository)(nil)
