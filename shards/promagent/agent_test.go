package promagent

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/prompb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type receiver struct {
	lock    sync.Mutex
	series  map[string]float64
	apiKeys map[string]bool
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := snappy.Decode(nil, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var wr prompb.WriteRequest
	if err = wr.Unmarshal(data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rc.lock.Lock()
	defer rc.lock.Unlock()
	rc.apiKeys[r.Header.Get("X-Api-Key")] = true
	for _, ts := range wr.Timeseries {
		var parts []string
		for _, l := range ts.Labels {
			parts = append(parts, l.Name+"="+l.Value)
		}
		for _, s := range ts.Samples {
			rc.series[strings.Join(parts, ",")] = s.Value
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rc *receiver) get(key string) (float64, bool) {
	rc.lock.Lock()
	defer rc.lock.Unlock()
	v, ok := rc.series[key]
	return v, ok
}

func TestScrapeToRemoteWrite(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "" {
			http.Error(w, "the Coroot API key must not be sent to targets", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintln(w, "# TYPE test_metric gauge")
		_, _ = fmt.Fprintln(w, `test_metric{a="b"} 42`)
	}))
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	require.NoError(t, err)

	rc := &receiver{series: map[string]float64{}, apiKeys: map[string]bool{}}
	rw := httptest.NewServer(rc)
	defer rw.Close()
	rwURL, err := url.Parse(rw.URL + "/v1/metrics")
	require.NoError(t, err)

	discoveryReloadInterval = model.Duration(100 * time.Millisecond)
	o := Options{
		Hostname:       testHostname,
		Endpoint:       rwURL,
		APIKey:         testAPIKey,
		ScrapeInterval: time.Second,
		ConfigFile: writeFile(t, t.TempDir(), "prometheus.yml", fmt.Sprintf(`
scrape_configs:
  - job_name: app
    static_configs: [{targets: ['%s']}]
`, targetURL.Host)),
	}
	cfg, err := BuildConfig(o)
	require.NoError(t, err)
	cfg.RemoteWriteConfigs[0].QueueConfig.BatchSendDeadline = model.Duration(100 * time.Millisecond)

	reg := prometheus.NewRegistry()
	a, err := StartWithConfig(cfg, t.TempDir(), reg)
	require.NoError(t, err)

	instance := testHostname + ":" + targetURL.Port()
	metric := fmt.Sprintf("__name__=test_metric,a=b,host=%s,instance=%s,job=app", testHostname, instance)
	up := fmt.Sprintf("__name__=up,host=%s,instance=%s,job=app", testHostname, instance)
	require.Eventually(t, func() bool {
		_, ok1 := rc.get(metric)
		_, ok2 := rc.get(up)
		return ok1 && ok2
	}, 30*time.Second, 100*time.Millisecond)
	v, _ := rc.get(metric)
	assert.Equal(t, 42.0, v)
	v, _ = rc.get(up)
	assert.Equal(t, 1.0, v)

	// the internal metrics pushed to Coroot exist (the queue metrics are unregistered on Stop)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	for name := range SelfMetrics {
		if name == "prometheus_remote_storage_samples_dropped_total" { // only created on the first drop
			continue
		}
		assert.True(t, names[name], name)
	}

	stopStart := time.Now()
	done := make(chan struct{})
	go func() {
		a.Stop()
		close(done)
	}()
	select {
	case <-done:
		t.Log("stop took", time.Since(stopStart))
	case <-time.After(RemoteFlushDeadline + 5*time.Second):
		t.Fatal("Stop took too long")
	}

	rc.lock.Lock()
	assert.Equal(t, map[string]bool{testAPIKey: true}, rc.apiKeys)
	rc.lock.Unlock()
}
