// Package relay re-exposes metric families gathered from one registry as metrics of another,
// e.g. a subset of the scrape manager's self-metrics or the latest results of synthetic probes.
package relay

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/klog/v2"
)

// Collector is an unchecked prometheus.Collector that gathers g on every collection and
// emits the families accepted by keep (all of them if keep is nil) as constant metrics.
// Gauges, counters, untyped metrics, summaries and classic histograms are supported.
type Collector struct {
	g    prometheus.Gatherer
	keep func(name string) bool
}

func New(g prometheus.Gatherer, keep func(name string) bool) *Collector {
	return &Collector{g: g, keep: keep}
}

// Describe sends nothing, which makes the collector unchecked:
// the set of relayed metrics isn't known in advance.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	mfs, err := c.g.Gather()
	if err != nil {
		klog.Warningln("failed to gather relayed metrics:", err)
	}
	for _, mf := range mfs {
		if c.keep != nil && !c.keep(mf.GetName()) {
			continue
		}
		for _, m := range mf.GetMetric() {
			if pm, err := convert(mf, m); err == nil && pm != nil {
				ch <- pm
			}
		}
	}
}

// Filter returns a Gatherer that only returns the families of g accepted by keep.
func Filter(g prometheus.Gatherer, keep func(name string) bool) prometheus.Gatherer {
	return prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
		mfs, err := g.Gather()
		res := mfs[:0]
		for _, mf := range mfs {
			if keep(mf.GetName()) {
				res = append(res, mf)
			}
		}
		return res, err
	})
}

func convert(mf *dto.MetricFamily, m *dto.Metric) (prometheus.Metric, error) {
	names := make([]string, 0, len(m.GetLabel()))
	values := make([]string, 0, len(m.GetLabel()))
	for _, l := range m.GetLabel() {
		names = append(names, l.GetName())
		values = append(values, l.GetValue())
	}
	desc := prometheus.NewDesc(mf.GetName(), mf.GetHelp(), names, nil)
	switch mf.GetType() {
	case dto.MetricType_GAUGE:
		return prometheus.NewConstMetric(desc, prometheus.GaugeValue, m.GetGauge().GetValue(), values...)
	case dto.MetricType_COUNTER:
		return prometheus.NewConstMetric(desc, prometheus.CounterValue, m.GetCounter().GetValue(), values...)
	case dto.MetricType_UNTYPED:
		return prometheus.NewConstMetric(desc, prometheus.UntypedValue, m.GetUntyped().GetValue(), values...)
	case dto.MetricType_SUMMARY:
		s := m.GetSummary()
		quantiles := make(map[float64]float64, len(s.GetQuantile()))
		for _, q := range s.GetQuantile() {
			quantiles[q.GetQuantile()] = q.GetValue()
		}
		return prometheus.NewConstSummary(desc, s.GetSampleCount(), s.GetSampleSum(), quantiles, values...)
	case dto.MetricType_HISTOGRAM:
		h := m.GetHistogram()
		if len(h.GetBucket()) == 0 { // native-only histogram
			return nil, nil
		}
		buckets := make(map[float64]uint64, len(h.GetBucket()))
		for _, b := range h.GetBucket() {
			buckets[b.GetUpperBound()] = b.GetCumulativeCount()
		}
		return prometheus.NewConstHistogram(desc, h.GetSampleCount(), h.GetSampleSum(), buckets, values...)
	}
	return nil, nil
}
