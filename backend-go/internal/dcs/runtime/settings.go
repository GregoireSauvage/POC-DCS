// Package runtime is a legacy package kept for compatibility during migration.
// Deprecated: prefer github.com/neoweyss/poc-dcs/backend-go/internal/config.DCSRuntime in new code.
package runtime

import (
	"strings"
	"sync"
)

type Settings struct {
	source     runtimeSource
	mu         sync.RWMutex
	dcsMode    string
	cacheLevel int
}

type runtimeSource interface {
	Set(mode *string, cacheLevel *int)
	Mode() string
	CacheLevel() int
	DcsEnabled() bool
}

func New(defaultMode string, defaultCacheLevel int) *Settings {
	mode := strings.ToLower(strings.TrimSpace(defaultMode))
	if mode == "" {
		mode = "on"
	}
	if defaultCacheLevel < 0 {
		defaultCacheLevel = 0
	}
	return &Settings{
		dcsMode:    mode,
		cacheLevel: defaultCacheLevel,
	}
}

func Wrap(source runtimeSource) *Settings {
	if source == nil {
		return New("on", 0)
	}
	return &Settings{source: source}
}

func (s *Settings) Set(mode *string, cacheLevel *int) {
	if s.source != nil {
		s.source.Set(mode, cacheLevel)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if mode != nil {
		m := strings.ToLower(strings.TrimSpace(*mode))
		if m == "" {
			m = "on"
		}
		s.dcsMode = m
	}
	if cacheLevel != nil {
		if *cacheLevel < 0 {
			s.cacheLevel = 0
		} else {
			s.cacheLevel = *cacheLevel
		}
	}
}

func (s *Settings) Mode() string {
	if s.source != nil {
		return s.source.Mode()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dcsMode
}

func (s *Settings) CacheLevel() int {
	if s.source != nil {
		return s.source.CacheLevel()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cacheLevel
}

func (s *Settings) DcsEnabled() bool {
	if s.source != nil {
		return s.source.DcsEnabled()
	}
	mode := s.Mode()
	return mode != "off" && mode != "false" && mode != "0" && mode != "no"
}
