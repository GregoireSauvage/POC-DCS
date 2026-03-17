package config

import (
	"strings"
	"sync"
)

type DCSRuntime struct {
	mu         sync.RWMutex
	dcsMode    string
	cacheLevel int
}

func NewDCSRuntime(defaultMode string, defaultCacheLevel int) *DCSRuntime {
	mode := strings.ToLower(strings.TrimSpace(defaultMode))
	if mode == "" {
		mode = "on"
	}
	if defaultCacheLevel < 0 {
		defaultCacheLevel = 0
	}
	return &DCSRuntime{
		dcsMode:    mode,
		cacheLevel: defaultCacheLevel,
	}
}

func (s *DCSRuntime) Set(mode *string, cacheLevel *int) {
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

func (s *DCSRuntime) Mode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dcsMode
}

func (s *DCSRuntime) CacheLevel() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cacheLevel
}

func (s *DCSRuntime) DcsEnabled() bool {
	mode := s.Mode()
	return mode != "off" && mode != "false" && mode != "0" && mode != "no"
}
