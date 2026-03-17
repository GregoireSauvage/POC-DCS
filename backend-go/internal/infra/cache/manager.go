package cache

import (
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type Options struct {
	MaxEntries        int
	ClassificationTTL time.Duration
	PDPTTL            time.Duration
	KMSTTL            time.Duration
	PepperTTL         time.Duration
}

type DecisionCache struct {
	store *TTL[string, service.Decision]
}

func newDecisionCache(maxEntries int, ttl time.Duration) *DecisionCache {
	return &DecisionCache{store: NewTTL[string, service.Decision](maxEntries, ttl)}
}

func (c *DecisionCache) Get(key string) (service.Decision, bool) {
	if c == nil {
		return service.Decision{}, false
	}
	return c.store.Get(key)
}

func (c *DecisionCache) Set(key string, value service.Decision) {
	if c == nil {
		return
	}
	c.store.Set(key, value, 0)
}

func (c *DecisionCache) Clear() {
	if c == nil {
		return
	}
	c.store.Clear()
}

type runtimeSettings interface {
	CacheLevel() int
}

type Manager struct {
	runtime runtimeSettings

	Classification *TTL[string, map[string]service.Classification]
	PDP            *DecisionCache
	KMS            *TTL[string, string]
	Pepper         *TTL[string, []byte]
}

func NewManager(rt runtimeSettings, opts Options) *Manager {
	return &Manager{
		runtime:        rt,
		Classification: NewTTL[string, map[string]service.Classification](opts.MaxEntries, opts.ClassificationTTL),
		PDP:            newDecisionCache(opts.MaxEntries, opts.PDPTTL),
		KMS:            NewTTL[string, string](opts.MaxEntries, opts.KMSTTL),
		Pepper:         NewTTL[string, []byte](8, opts.PepperTTL),
	}
}

func (m *Manager) LevelEnabled(level int) bool {
	if m == nil || m.runtime == nil {
		return false
	}
	return m.runtime.CacheLevel() >= level
}

func (m *Manager) ClearAll() {
	m.Classification.Clear()
	m.PDP.Clear()
	m.KMS.Clear()
	m.Pepper.Clear()
}
