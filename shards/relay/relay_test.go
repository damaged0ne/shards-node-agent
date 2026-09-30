package relay

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollector(t *testing.T) {
	src := prometheus.NewRegistry()
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "g", Help: "gauge"}, []string{"a"})
	g.WithLabelValues("x").Set(1.5)
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "c_total", Help: "counter"})
	c.Add(3)
	h := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "h", Help: "histogram", Buckets: []float64{1, 10}})
	h.Observe(0.5)
	h.Observe(5)
	s := prometheus.NewSummary(prometheus.SummaryOpts{Name: "s", Help: "summary", Objectives: map[float64]float64{0.5: 0.05}})
	s.Observe(2)
	dropped := prometheus.NewGauge(prometheus.GaugeOpts{Name: "dropped", Help: "dropped"})
	src.MustRegister(g, c, h, s, dropped)

	dst := prometheus.NewRegistry()
	wrapped := prometheus.WrapRegistererWith(prometheus.Labels{"machine_id": "m1"}, dst)
	wrapped.MustRegister(New(src, func(name string) bool { return name != "dropped" }))

	expected := `
# HELP c_total counter
# TYPE c_total counter
c_total{machine_id="m1"} 3
# HELP g gauge
# TYPE g gauge
g{a="x",machine_id="m1"} 1.5
# HELP h histogram
# TYPE h histogram
h_bucket{machine_id="m1",le="1"} 1
h_bucket{machine_id="m1",le="10"} 2
h_bucket{machine_id="m1",le="+Inf"} 2
h_sum{machine_id="m1"} 5.5
h_count{machine_id="m1"} 2
# HELP s summary
# TYPE s summary
s{machine_id="m1",quantile="0.5"} 2
s_sum{machine_id="m1"} 2
s_count{machine_id="m1"} 1
`
	require.NoError(t, testutil.GatherAndCompare(dst, strings.NewReader(expected)))

	mfs, err := Filter(src, func(name string) bool { return name == "dropped" }).Gather()
	require.NoError(t, err)
	require.Len(t, mfs, 1)
	assert.Equal(t, "dropped", mfs[0].GetName())
}
