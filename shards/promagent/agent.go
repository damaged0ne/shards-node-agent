package promagent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/scrape"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/agent"
	"github.com/prometheus/prometheus/util/logging"
	"k8s.io/klog/v2"
)

// RemoteFlushDeadline bounds how long pending samples are flushed on shutdown.
const RemoteFlushDeadline = 5 * time.Second

// discoveryReloadInterval is how often the scrape manager applies discovered target changes (overridden in tests).
var discoveryReloadInterval = model.Duration(5 * time.Second)

// SelfMetrics are the agent's internal metrics that are also pushed to Coroot
// (all of them are exposed on the node-agent's /metrics).
var SelfMetrics = map[string]bool{
	"prometheus_remote_storage_samples_total":                        true,
	"prometheus_remote_storage_samples_failed_total":                 true,
	"prometheus_remote_storage_samples_retried_total":                true,
	"prometheus_remote_storage_samples_dropped_total":                true,
	"prometheus_remote_storage_samples_pending":                      true,
	"prometheus_remote_storage_highest_timestamp_in_seconds":         true,
	"prometheus_remote_storage_queue_highest_sent_timestamp_seconds": true,
	"prometheus_remote_storage_shards":                               true,
	"prometheus_sd_discovered_targets":                               true,
	"prometheus_target_scrape_pool_targets":                          true,
}

// Agent is a Prometheus agent: discovery manager -> scrape manager -> agent WAL -> remote write.
type Agent struct {
	cancel    context.CancelFunc
	discovery *discovery.Manager
	scrape    *scrape.Manager
	storage   storage.Storage
	wg        sync.WaitGroup
	stopOnce  sync.Once
}

// Start builds the configuration and starts the agent. Its internal metrics are registered on reg,
// the WAL is kept in walDir. httpOpts are applied to the scrape clients.
func Start(o Options, walDir string, reg prometheus.Registerer, httpOpts ...commoncfg.HTTPClientOption) (*Agent, error) {
	cfg, err := BuildConfig(o)
	if err != nil {
		return nil, err
	}
	return StartWithConfig(cfg, walDir, reg, httpOpts...)
}

// StartWithConfig starts the agent with a configuration built by BuildConfig.
func StartWithConfig(cfg *config.Config, walDir string, reg prometheus.Registerer, httpOpts ...commoncfg.HTTPClientOption) (*Agent, error) {
	if len(cfg.RemoteWriteConfigs) == 0 {
		return nil, errors.New("no remote_write destination configured")
	}
	logger := NewLogger("scrape")

	var db atomic.Pointer[agent.DB]
	startTime := func() (int64, error) {
		if d := db.Load(); d != nil {
			return d.StartTime()
		}
		return math.MaxInt64, tsdb.ErrNotReady
	}
	sm := &readyScrapeManager{}
	rs := remote.NewStorage(logger, reg, startTime, walDir, RemoteFlushDeadline, sm)
	if err := rs.ApplyConfig(cfg); err != nil {
		_ = rs.Close()
		return nil, fmt.Errorf("failed to apply remote write config: %w", err)
	}
	d, err := agent.Open(logger, reg, rs, walDir, agent.DefaultOptions())
	if err != nil {
		_ = rs.Close()
		return nil, fmt.Errorf("failed to open the WAL: %w", err)
	}
	db.Store(d)
	d.SetWriteNotified(rs)
	fanout := storage.NewFanout(logger, d, rs)

	a := &Agent{storage: fanout}
	fail := func(err error) (*Agent, error) {
		_ = fanout.Close()
		return nil, err
	}

	sdMetrics, err := discovery.CreateAndRegisterSDMetrics(reg)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.discovery = discovery.NewManager(ctx, logger, reg, sdMetrics, discovery.Name("scrape"))
	if a.discovery == nil {
		cancel()
		return fail(errors.New("failed to create the discovery manager"))
	}
	sdConfigs := map[string]discovery.Configs{}
	for _, sc := range cfg.ScrapeConfigs {
		sdConfigs[sc.JobName] = sc.ServiceDiscoveryConfigs
	}
	if err = a.discovery.ApplyConfig(sdConfigs); err != nil {
		cancel()
		return fail(err)
	}

	newFailureLogger := func(s string) (*logging.JSONFileLogger, error) { return logging.NewJSONFileLogger(s) }
	a.scrape, err = scrape.NewManager(&scrape.Options{HTTPClientOptions: httpOpts, DiscoveryReloadInterval: discoveryReloadInterval}, logger, newFailureLogger, fanout, reg)
	if err != nil {
		cancel()
		return fail(err)
	}
	if err = a.scrape.ApplyConfig(cfg); err != nil {
		cancel()
		return fail(err)
	}
	sm.Set(a.scrape)

	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		if err := a.discovery.Run(); err != nil && !errors.Is(err, context.Canceled) {
			klog.Errorln("discovery manager stopped:", err)
		}
	}()
	go func() {
		defer a.wg.Done()
		if err := a.scrape.Run(a.discovery.SyncCh()); err != nil {
			klog.Errorln("scrape manager stopped:", err)
		}
	}()
	klog.Infof("scraping %d job(s), remote writing to %d destination(s)", len(cfg.ScrapeConfigs), len(cfg.RemoteWriteConfigs))
	return a, nil
}

// Stop stops discovery and scraping, then flushes the pending samples (for at most
// RemoteFlushDeadline) and closes the WAL.
func (a *Agent) Stop() {
	a.stopOnce.Do(func() {
		a.cancel()
		a.scrape.Stop()
		a.wg.Wait()
		if err := a.storage.Close(); err != nil {
			klog.Warningln("failed to close the scrape storage:", err)
		}
	})
}

type readyScrapeManager struct {
	mu sync.RWMutex
	m  *scrape.Manager
}

func (rm *readyScrapeManager) Set(m *scrape.Manager) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.m = m
}

func (rm *readyScrapeManager) Get() (*scrape.Manager, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if rm.m == nil {
		return nil, errors.New("scrape manager not ready")
	}
	return rm.m, nil
}
