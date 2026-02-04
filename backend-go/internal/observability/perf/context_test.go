package perf

import (
	"context"
	"testing"
	"time"
)

func TestContext_SpanAggregation(t *testing.T) {
	ctx, p := NewContext(context.Background())

	stop := Span(ctx, "pdp_ms")
	time.Sleep(5 * time.Millisecond)
	stop()

	stop = Span(ctx, "pdp_ms")
	time.Sleep(5 * time.Millisecond)
	stop()

	metrics := p.Metrics()
	if metrics["pdp_ms"] <= 0 {
		t.Fatalf("expected positive pdp_ms, got %v", metrics["pdp_ms"])
	}
	if p.TotalMS() <= 0 {
		t.Fatalf("expected positive total ms")
	}
}
