package cache

import (
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
)

type Options struct {
	MaxEntries        int
	ClassificationTTL time.Duration
	PDPTTL            time.Duration
	KMSTTL            time.Duration
	PepperTTL         time.Duration
}

type Manager struct {
	runtime *runtime.Settings

	Classification *TTL[string, map[string]types.Classification]
	PDP            *TTL[string, types.Decision]
	KMS            *TTL[string, string]
	Pepper         *TTL[string, []byte]
}

func NewManager(rt *runtime.Settings, opts Options) *Manager {
	return &Manager{
		runtime:        rt,
		Classification: NewTTL[string, map[string]types.Classification](opts.MaxEntries, opts.ClassificationTTL),
		PDP:            NewTTL[string, types.Decision](opts.MaxEntries, opts.PDPTTL),
		KMS:            NewTTL[string, string](opts.MaxEntries, opts.KMSTTL),
		Pepper:         NewTTL[string, []byte](8, opts.PepperTTL),
	}
}

func (m *Manager) LevelEnabled(level int) bool {
	return m.runtime.CacheLevel() >= level
}

func (m *Manager) ClearAll() {
	m.Classification.Clear()
	m.PDP.Clear()
	m.KMS.Clear()
	m.Pepper.Clear()
}
