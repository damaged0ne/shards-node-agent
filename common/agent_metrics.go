package common

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Self-observability metrics of the agent. They make data loss visible:
// dropped eBPF samples, undecodable events, recovered panics, etc.
var (
	AgentEbpfLostSamples = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_agent_ebpf_lost_samples_total",
		Help: "Number of eBPF perf buffer samples lost because the buffer was full",
	}, []string{"buffer"})

	AgentEbpfDecodeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_agent_ebpf_decode_errors_total",
		Help: "Number of eBPF events that could not be decoded",
	}, []string{"buffer"})

	AgentL7ParseErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_agent_l7_parse_errors_total",
		Help: "Number of L7 payloads that could not be parsed",
	}, []string{"protocol"})

	AgentRecoveredPanics = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_agent_recovered_panics_total",
		Help: "Number of panics recovered by the agent",
	}, []string{"component"})

	AgentRemoteWriteFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "node_agent_remote_write_failures_total",
		Help: "Number of failed attempts to send metrics to the collector",
	})

	AgentEventsQueueLength = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_agent_events_queue_length",
		Help: "Number of eBPF events waiting to be processed",
	})
)

func RegisterAgentMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		AgentEbpfLostSamples,
		AgentEbpfDecodeErrors,
		AgentL7ParseErrors,
		AgentRecoveredPanics,
		AgentRemoteWriteFailures,
		AgentEventsQueueLength,
	} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}
