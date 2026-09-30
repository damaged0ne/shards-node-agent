package tracing

import (
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"golang.org/x/sys/unix"
)

func TestMonotonicToTime(t *testing.T) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	mono := uint64(ts.Nano()) - uint64(5*time.Second)
	got := MonotonicToTime(mono)
	expected := time.Now().Add(-5 * time.Second)
	if d := got.Sub(expected); d > 100*time.Millisecond || d < -100*time.Millisecond {
		t.Fatalf("unexpected time: got %s, expected ~%s", got, expected)
	}
}

func TestSpanTimestamps(t *testing.T) {
	samplingRate = 1.0
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	tracer := &Tracer{otel: provider.Tracer("test")}

	end := time.Now().Add(-time.Minute)
	tracer.NewTraceAt(common.HostPortWithEmptyIP("example.com", 80), end).HttpRequest("GET", "/", 200, time.Second)
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if !spans[0].EndTime.Equal(end) || !spans[0].StartTime.Equal(end.Add(-time.Second)) {
		t.Fatalf("unexpected span times: %s - %s", spans[0].StartTime, spans[0].EndTime)
	}
}
