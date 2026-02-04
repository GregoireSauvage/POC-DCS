package perf

import (
	"context"
	"sync"
	"time"
)

type keyType string

const perfKey keyType = "perf_context"

type Context struct {
	start   time.Time
	mu      sync.Mutex
	metrics map[string]float64
}

func New() *Context {
	return &Context{
		start:   time.Now(),
		metrics: map[string]float64{},
	}
}

func NewContext(parent context.Context) (context.Context, *Context) {
	p := New()
	return context.WithValue(parent, perfKey, p), p
}

func FromContext(ctx context.Context) *Context {
	v := ctx.Value(perfKey)
	if v == nil {
		return nil
	}
	p, _ := v.(*Context)
	return p
}

func (p *Context) Add(key string, ms float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics[key] += ms
}

func (p *Context) Metrics() map[string]float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]float64, len(p.metrics))
	for k, v := range p.metrics {
		out[k] = v
	}
	return out
}

func (p *Context) TotalMS() float64 {
	return float64(time.Since(p.start).Microseconds()) / 1000.0
}

func Span(ctx context.Context, key string) func() {
	start := time.Now()
	return func() {
		p := FromContext(ctx)
		if p == nil {
			return
		}
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		if ms <= 0 {
			ms = 0.001
		}
		p.Add(key, ms)
	}
}
