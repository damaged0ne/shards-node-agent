package tracing

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	MemcacheDBItemKeyName attribute.Key = "db.memcached.item"
)

var (
	spanProcessor       sdktrace.SpanProcessor
	batcher             sdktrace.TracerProviderOption
	commonResourceAttrs []attribute.KeyValue
	agentVersion        string
	initialized         bool
	samplingRate        float64
)

func Init(machineId, hostname, version string) {
	endpointUrl := *flags.TracesEndpoint
	if endpointUrl == nil {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
	}

	samplingRate = *flags.TracesSampling
	if samplingRate < 0.0 || samplingRate > 1.0 {
		klog.Warningf("invalid traces-sampling value %f, must be between 0.0 and 1.0, using default 1.0", samplingRate)
		samplingRate = 1.0
	}
	if samplingRate < 1.0 {
		klog.Infof("trace sampling rate set to %f", samplingRate)
	}
	klog.Infoln("OpenTelemetry traces collector endpoint:", endpointUrl.String())
	path := endpointUrl.Path
	if path == "" {
		path = "/"
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpointUrl.Host),
		otlptracehttp.WithURLPath(path),
		otlptracehttp.WithHeaders(api.AuthHeaders(*flags.ApiKey)),
		otlptracehttp.WithTLSClientConfig(api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify)),
	}
	if endpointUrl.Scheme != "https" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	client := otlptracehttp.NewClient(opts...)
	exporter, err := otlptrace.New(context.Background(), client)
	if err != nil {
		klog.Exitln(err)
	}

	// A single batch span processor is shared by all per-container tracer providers.
	spanProcessor = sdktrace.NewBatchSpanProcessor(exporter)
	batcher = sdktrace.WithSpanProcessor(spanProcessor)
	commonResourceAttrs = []attribute.KeyValue{semconv.HostName(hostname), semconv.HostID(machineId)}
	agentVersion = version
	initialized = true
}

// Shutdown flushes buffered spans and shuts down the exporter. It should be called on agent exit.
func Shutdown(ctx context.Context) {
	if spanProcessor == nil {
		return
	}
	if err := spanProcessor.Shutdown(ctx); err != nil {
		klog.Warningln("failed to shutdown the traces exporter:", err)
	}
}

// MonotonicToTime converts a CLOCK_MONOTONIC timestamp in nanoseconds (as returned by bpf_ktime_get_ns())
// to wall clock time.
func MonotonicToTime(ns uint64) time.Time {
	now := time.Now()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return now
	}
	return now.Add(-time.Duration(ts.Nano() - int64(ns)))
}

type Tracer struct {
	otel trace.Tracer
}

func shouldSample() bool {
	if samplingRate >= 1.0 {
		return true
	}
	if samplingRate <= 0.0 {
		return false
	}

	return rand.Float64() < samplingRate
}

func GetContainerTracer(containerId string) *Tracer {
	if !initialized {
		return &Tracer{otel: nil}
	}
	provider := sdktrace.NewTracerProvider(
		batcher,
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			append(
				commonResourceAttrs,
				semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
				semconv.ContainerID(containerId),
			)...,
		)),
	)
	return &Tracer{otel: provider.Tracer("coroot-node-agent", trace.WithInstrumentationVersion(agentVersion))}
}

func (t *Tracer) NewTrace(destination common.HostPort) *Trace {
	return t.NewTraceAt(destination, time.Time{})
}

// NewTraceAt is like NewTrace, but spans end at the given time (e.g. the kernel event time converted
// with MonotonicToTime) rather than at the time they are created. A zero end means time.Now().
func (t *Tracer) NewTraceAt(destination common.HostPort, end time.Time) *Trace {
	return &Trace{tracer: t, destination: destination, end: end, commonAttrs: []attribute.KeyValue{
		semconv.NetPeerName(destination.Host()),
		semconv.NetPeerPort(int(destination.Port())),
	}}
}

type Trace struct {
	tracer      *Tracer
	destination common.HostPort
	end         time.Time
	commonAttrs []attribute.KeyValue
}

func (t *Trace) createSpan(name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	if t.tracer.otel == nil {
		return
	}
	if !shouldSample() {
		return
	}

	end := t.end
	if end.IsZero() {
		end = time.Now()
	}
	start := end.Add(-duration)
	_, span := t.tracer.otel.Start(context.Background(), name, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(attrs...)
	span.SetAttributes(t.commonAttrs...)
	if error {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func (t *Trace) HttpRequest(method, path string, status l7.Status, duration time.Duration) {
	if t == nil || method == "" {
		return
	}
	t.createSpan(method, duration, status >= 400,
		semconv.HTTPURL(fmt.Sprintf("http://%s%s", t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	)
}

func (t *Trace) Http2Request(method, path, scheme string, status, grpcStatus l7.Status, duration time.Duration) {
	if t == nil {
		return
	}
	if method == "" {
		method = "unknown"
	}
	if path == "" {
		path = "/unknown"
	}
	if scheme == "" {
		scheme = "unknown"
	}

	attrs := []attribute.KeyValue{
		semconv.HTTPURL(fmt.Sprintf("%s://%s%s", scheme, t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	}
	if grpcStatus >= 0 {
		attrs = append(attrs, semconv.RPCGRPCStatusCodeKey.Int(int(grpcStatus)))
	}
	t.createSpan(method, duration, status > 400 || grpcStatus > 0, attrs...)
}

func (t *Trace) PostgresQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemPostgreSQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMySQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMongoDB,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MemcachedQuery(cmd string, items []string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	attrs := []attribute.KeyValue{
		semconv.DBSystemMemcached,
		semconv.DBOperation(cmd),
	}
	if len(items) == 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.String(items[0]))
	} else if len(items) > 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.StringSlice(items))
	}
	t.createSpan(cmd, duration, error, attrs...)
}

func (t *Trace) RedisQuery(cmd, args string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	statement := cmd
	if args != "" {
		statement += " " + args
	}
	t.createSpan(cmd, duration, error,
		semconv.DBSystemRedis,
		semconv.DBOperation(cmd),
		semconv.DBStatement(statement),
	)
}

func (t *Trace) ClickhouseQuery(query string, error bool, duration time.Duration) {
	if t == nil {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemClickhouse,
		semconv.DBStatement(query),
	)
}

func (t *Trace) ZookeeperRequest(op string, args string, status l7.Status, duration time.Duration) {
	if t == nil {
		return
	}
	if op == "" {
		return
	}
	statement := op
	if args != "" {
		statement += " " + args
	}
	t.createSpan(op, duration, status.Zookeeper() != "ok",
		semconv.DBSystemKey.String("zookeeper"),
		semconv.DBOperation(op),
		semconv.DBStatementKey.String(statement),
		attribute.Key("zookeeper.status_code").Int(int(status)),
	)
}
