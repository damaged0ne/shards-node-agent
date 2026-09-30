// Package probes runs synthetic probes (a blackbox_exporter replacement) with the blackbox_exporter
// probers, so the metric names are the same: probe_success, probe_duration_seconds,
// probe_http_status_code, probe_ssl_earliest_cert_expiry, ...
package probes

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bbconfig "github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"gopkg.in/yaml.v2"

	"github.com/coroot/coroot-node-agent/shards/promagent"
	"github.com/coroot/coroot-node-agent/shards/relay"
)

const (
	defaultTimeout = 10 * time.Second
	redacted       = "<secret>"
)

// Config is the content of --probe-config-file.
type Config struct {
	Probes []*Probe `yaml:"probes"`
}

// Probe is a single probe. The http, tcp, icmp and dns sections have the syntax of the
// corresponding sections of a blackbox_exporter module.
type Probe struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"`
	Target   string            `yaml:"target"`
	Interval model.Duration    `yaml:"interval,omitempty"`
	Timeout  model.Duration    `yaml:"timeout,omitempty"`
	Labels   map[string]string `yaml:"labels,omitempty"`

	HTTP bbconfig.HTTPProbe `yaml:"http,omitempty"`
	TCP  bbconfig.TCPProbe  `yaml:"tcp,omitempty"`
	ICMP bbconfig.ICMPProbe `yaml:"icmp,omitempty"`
	DNS  bbconfig.DNSProbe  `yaml:"dns,omitempty"`
}

func (p *Probe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*p = Probe{
		HTTP: bbconfig.DefaultHTTPProbe,
		TCP:  bbconfig.DefaultTCPProbe,
		ICMP: bbconfig.DefaultICMPProbe,
		DNS:  bbconfig.DefaultDNSProbe,
	}
	type plain Probe
	return unmarshal((*plain)(p))
}

var reservedLabels = map[string]bool{
	model.JobLabel: true, model.InstanceLabel: true, "machine_id": true, "system_uuid": true,
}

// LoadFile reads and validates a probe config file. defaultInterval is used for probes without an interval.
func LoadFile(path string, defaultInterval time.Duration) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Load(data, defaultInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid probe config file %s: %w", path, err)
	}
	for _, p := range cfg.Probes {
		p.HTTP.HTTPClientConfig.SetDirectory(filepath.Dir(path))
		p.TCP.TLSConfig.SetDirectory(filepath.Dir(path))
		p.DNS.TLSConfig.SetDirectory(filepath.Dir(path))
	}
	return cfg, nil
}

// Load parses and validates a probe config.
func Load(data []byte, defaultInterval time.Duration) (*Config, error) {
	cfg := &Config{}
	if err := yaml.UnmarshalStrict(data, cfg); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for i, p := range cfg.Probes {
		if p == nil {
			return nil, fmt.Errorf("probe #%d is empty", i+1)
		}
		if p.Name == "" {
			return nil, fmt.Errorf("probe #%d: name is empty", i+1)
		}
		if names[p.Name] {
			return nil, fmt.Errorf("duplicate probe name %q", p.Name)
		}
		names[p.Name] = true
		if err := p.validate(defaultInterval); err != nil {
			return nil, fmt.Errorf("probe %q: %w", p.Name, err)
		}
	}
	return cfg, nil
}

func (p *Probe) validate(defaultInterval time.Duration) error {
	switch p.Type {
	case "http", "tcp", "icmp", "dns":
	default:
		return fmt.Errorf("unknown type %q, must be one of http, tcp, icmp, dns", p.Type)
	}
	if p.Target == "" {
		return fmt.Errorf("target is empty")
	}
	if p.Type == "dns" && p.DNS.QueryName == "" {
		return fmt.Errorf("dns.query_name is empty")
	}
	if p.Interval <= 0 {
		p.Interval = model.Duration(defaultInterval)
	}
	if p.Interval <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	if p.Timeout <= 0 {
		p.Timeout = model.Duration(min(defaultTimeout, time.Duration(p.Interval)))
	}
	if p.Timeout > p.Interval {
		return fmt.Errorf("timeout (%s) is greater than interval (%s)", p.Timeout, p.Interval)
	}
	for k := range p.Labels {
		if !model.LabelName(k).IsValidLegacy() || strings.HasPrefix(k, "__") {
			return fmt.Errorf("invalid label name %q", k)
		}
		if reservedLabels[k] {
			return fmt.Errorf("label %q is reserved", k)
		}
	}
	return nil
}

// String returns the configuration with secrets (and HTTP header values) masked.
func (c *Config) String() string {
	cp := Config{}
	for _, p := range c.Probes {
		pc := *p
		if len(pc.HTTP.Headers) > 0 {
			pc.HTTP.Headers = make(map[string]string, len(p.HTTP.Headers))
			for k := range p.HTTP.Headers {
				pc.HTTP.Headers[k] = redacted
			}
		}
		pc.Target = promagent.Redact(pc.Target)
		cp.Probes = append(cp.Probes, &pc)
	}
	data, err := yaml.Marshal(cp)
	if err != nil {
		return fmt.Sprintf("<error creating probe config string: %s>", err)
	}
	return string(data)
}

func (p *Probe) module() bbconfig.Module {
	return bbconfig.Module{
		Prober:  p.Type,
		Timeout: time.Duration(p.Timeout),
		HTTP:    p.HTTP,
		TCP:     p.TCP,
		ICMP:    p.ICMP,
		DNS:     p.DNS,
	}
}

// Runner runs the probes and exposes the results of their last runs as a prometheus.Collector.
type Runner struct {
	*relay.Collector

	probes  []*Probe
	lock    sync.RWMutex
	results map[string][]*dto.MetricFamily

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRunner creates a runner, Start starts the probes.
func NewRunner(cfg *Config) *Runner {
	r := &Runner{probes: cfg.Probes, results: map[string][]*dto.MetricFamily{}}
	r.Collector = relay.New(prometheus.GathererFunc(r.gather), nil)
	return r
}

func (r *Runner) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	for _, p := range r.probes {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.loop(ctx, p)
		}()
	}
}

func (r *Runner) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
}

func (r *Runner) loop(ctx context.Context, p *Probe) {
	interval := time.Duration(p.Interval)
	// spread the probes over the interval
	select {
	case <-ctx.Done():
		return
	case <-time.After(rand.N(min(interval, 5*time.Second))):
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		r.RunOnce(ctx, p)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce runs the probe and stores its metrics.
func (r *Runner) RunOnce(ctx context.Context, p *Probe) {
	mfs := Run(ctx, p)
	r.lock.Lock()
	r.results[p.Name] = mfs
	r.lock.Unlock()
}

func (r *Runner) gather() ([]*dto.MetricFamily, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	var res []*dto.MetricFamily
	for _, p := range r.probes {
		res = append(res, r.results[p.Name]...)
	}
	return res, nil
}

// Probe failures are reported by probe_success, so the probers' logs are only written with -v >= 1.
var logger = promagent.NewQuietLogger("probe")

// Run runs the probe once and returns its metrics labeled with job=<name>, instance=<target> and the probe labels.
func Run(ctx context.Context, p *Probe) []*dto.MetricFamily {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.Timeout))
	defer cancel()

	success := prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_success", Help: "Displays whether or not the probe was a success"})
	duration := prometheus.NewGauge(prometheus.GaugeOpts{Name: "probe_duration_seconds", Help: "Returns how long the probe took to complete in seconds"})
	reg := prometheus.NewRegistry()
	reg.MustRegister(success, duration)

	start := time.Now()
	ok := prober.Probers[p.Type](ctx, p.Target, p.module(), reg, logger.With("probe", p.Name))
	duration.Set(time.Since(start).Seconds())
	if ok {
		success.Set(1)
	}
	mfs, err := reg.Gather()
	if err != nil {
		logger.Warn("failed to gather probe metrics", "probe", p.Name, "err", err)
	}
	extra := map[string]string{model.JobLabel: p.Name, model.InstanceLabel: promagent.Redact(p.Target)}
	for k, v := range p.Labels {
		extra[k] = v
	}
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			m.Label = addLabels(m.Label, extra)
		}
	}
	return mfs
}

func addLabels(lps []*dto.LabelPair, extra map[string]string) []*dto.LabelPair {
	res := make([]*dto.LabelPair, 0, len(lps)+len(extra))
	for _, lp := range lps {
		if _, ok := extra[lp.GetName()]; !ok {
			res = append(res, lp)
		}
	}
	for k, v := range extra {
		res = append(res, &dto.LabelPair{Name: &k, Value: &v})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].GetName() < res[j].GetName() })
	return res
}
