// Package promagent turns the node-agent into a local Prometheus agent: it discovers and scrapes
// targets on the node (Docker containers labeled with prometheus.io/*, plus the jobs of an optional
// Prometheus configuration file) and remote-writes the samples to Coroot through an agent-mode WAL.
package promagent

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/moby"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/relabel"
	"gopkg.in/yaml.v2"

	// Service discovery mechanisms available in --scrape-config-file.
	_ "github.com/prometheus/prometheus/discovery/dns"
	_ "github.com/prometheus/prometheus/discovery/file"
	_ "github.com/prometheus/prometheus/discovery/http"
)

const (
	// DockerJobName is the scrape pool of the containers discovered with the prometheus.io/* labels.
	DockerJobName = "docker"
	// CorootRemoteWriteName is the name of the remote_write destination pointing to Coroot.
	CorootRemoteWriteName = "coroot"
	// HostLabel is added to every series written by the agent (as an external label).
	HostLabel = "host"

	RemoteWriteTimeout    = 30 * time.Second
	dockerRefreshInterval = 15 * time.Second

	dockerLabelPrefix = model.MetaLabelPrefix + "docker_container_label_"
	dockerScrapeLabel = "prometheus.io/scrape"
)

// Options configures the agent.
type Options struct {
	// Hostname is used for the host external label and in the instance label of local targets.
	Hostname string

	// Endpoint is Coroot's remote write endpoint (e.g. http://coroot:8080/v1/metrics), nil disables it.
	Endpoint           *url.URL
	APIKey             string
	CAFile             string
	InsecureSkipVerify bool

	// ScrapeInterval is the default global scrape_interval.
	ScrapeInterval time.Duration

	// ConfigFile is an optional Prometheus configuration file (scrape_configs, remote_write, global).
	ConfigFile string

	// DockerHost is the Docker daemon address used for container discovery, "" disables it.
	DockerHost string
	// ComposeGrouping must match the --compose-grouping flag to compute Coroot's container_id.
	ComposeGrouping bool
}

// BuildConfig assembles the Prometheus configuration of the agent from the options.
func BuildConfig(o Options) (*config.Config, error) {
	var content []byte
	dir := ""
	if o.ConfigFile != "" {
		var err error
		if content, err = os.ReadFile(o.ConfigFile); err != nil {
			return nil, err
		}
		dir = filepath.Dir(o.ConfigFile)
	}
	cfg, err := loadConfig(content, o.ScrapeInterval)
	if err != nil {
		if o.ConfigFile != "" {
			return nil, fmt.Errorf("invalid scrape config file %s: %w", o.ConfigFile, err)
		}
		return nil, err
	}
	if dir != "" {
		cfg.SetDirectory(dir)
	}

	// Resolve scrape_config_files so that all the jobs are in ScrapeConfigs.
	scfgs, err := cfg.GetScrapeConfigs()
	if err != nil {
		return nil, err
	}
	cfg.ScrapeConfigs, cfg.ScrapeConfigFiles = scfgs, nil
	for _, sc := range cfg.ScrapeConfigs {
		if o.DockerHost != "" && sc.JobName == DockerJobName {
			return nil, fmt.Errorf("job name %q is reserved for Docker container discovery", DockerJobName)
		}
		sc.RelabelConfigs = append(sc.RelabelConfigs, localInstanceRelabelConfig(o.Hostname))
	}
	if o.DockerHost != "" {
		sc := DockerScrapeConfig(o.DockerHost, o.Hostname, o.ComposeGrouping)
		if err := sc.Validate(cfg.GlobalConfig); err != nil {
			return nil, err
		}
		cfg.ScrapeConfigs = append(cfg.ScrapeConfigs, sc)
	}

	for _, rw := range cfg.RemoteWriteConfigs {
		if rw.Name == CorootRemoteWriteName {
			return nil, fmt.Errorf("remote_write name %q is reserved", CorootRemoteWriteName)
		}
		secretHeaders(rw)
	}
	if o.Endpoint != nil {
		rw := corootRemoteWriteConfig(o)
		if err := rw.HTTPClientConfig.Validate(); err != nil {
			return nil, err
		}
		cfg.RemoteWriteConfigs = append([]*config.RemoteWriteConfig{rw}, cfg.RemoteWriteConfigs...)
	}

	if o.Hostname != "" && !cfg.GlobalConfig.ExternalLabels.Has(HostLabel) {
		b := labels.NewBuilder(cfg.GlobalConfig.ExternalLabels)
		b.Set(HostLabel, o.Hostname)
		cfg.GlobalConfig.ExternalLabels = b.Labels()
	}
	return cfg, nil
}

// loadConfig parses a Prometheus configuration, using scrapeInterval as the default global scrape_interval.
func loadConfig(content []byte, scrapeInterval time.Duration) (*config.Config, error) {
	var doc yaml.MapSlice
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, err
	}
	if scrapeInterval > 0 {
		doc = setDefault(doc, "global", "scrape_interval", model.Duration(scrapeInterval).String())
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(string(data), NewLogger("scrape config"))
	if err != nil {
		return nil, err
	}
	// Same restrictions as Prometheus in agent mode.
	switch {
	case len(cfg.AlertingConfig.AlertmanagerConfigs) > 0 || len(cfg.AlertingConfig.AlertRelabelConfigs) > 0:
		return nil, errors.New("field alerting is not allowed in agent mode")
	case len(cfg.RuleFiles) > 0:
		return nil, errors.New("field rule_files is not allowed in agent mode")
	case len(cfg.RemoteReadConfigs) > 0:
		return nil, errors.New("field remote_read is not allowed in agent mode")
	}
	return cfg, nil
}

// setDefault sets doc[section][key] = value unless it's already set.
func setDefault(doc yaml.MapSlice, section, key string, value interface{}) yaml.MapSlice {
	for i, item := range doc {
		if item.Key != section {
			continue
		}
		s, _ := item.Value.(yaml.MapSlice)
		for _, kv := range s {
			if kv.Key == key {
				return doc
			}
		}
		doc[i].Value = append(s, yaml.MapItem{Key: key, Value: value})
		return doc
	}
	return append(doc, yaml.MapItem{Key: section, Value: yaml.MapSlice{{Key: key, Value: value}}})
}

// secretHeaders moves the plain `headers` of a remote_write config to http_headers secrets,
// so that they are masked whenever the configuration is marshaled.
func secretHeaders(rw *config.RemoteWriteConfig) {
	if len(rw.Headers) == 0 {
		return
	}
	if rw.HTTPClientConfig.HTTPHeaders == nil {
		rw.HTTPClientConfig.HTTPHeaders = &commoncfg.Headers{Headers: map[string]commoncfg.Header{}}
	}
	for k, v := range rw.Headers {
		h := rw.HTTPClientConfig.HTTPHeaders.Headers[k]
		h.Secrets = append(h.Secrets, commoncfg.Secret(v))
		rw.HTTPClientConfig.HTTPHeaders.Headers[k] = h
	}
	rw.Headers = nil
}

func corootRemoteWriteConfig(o Options) *config.RemoteWriteConfig {
	rw := config.DefaultRemoteWriteConfig
	rw.Name = CorootRemoteWriteName
	rw.URL = &commoncfg.URL{URL: o.Endpoint}
	rw.RemoteTimeout = model.Duration(RemoteWriteTimeout)
	// Coroot only needs the samples.
	rw.MetadataConfig.Send = false
	rw.HTTPClientConfig = commoncfg.DefaultHTTPClientConfig
	rw.HTTPClientConfig.TLSConfig = commoncfg.TLSConfig{CAFile: o.CAFile, InsecureSkipVerify: o.InsecureSkipVerify}
	rw.HTTPClientConfig.ProxyConfig = commoncfg.ProxyConfig{ProxyFromEnvironment: true}
	if o.APIKey != "" {
		rw.HTTPClientConfig.HTTPHeaders = &commoncfg.Headers{Headers: map[string]commoncfg.Header{
			"X-Api-Key": {Secrets: []commoncfg.Secret{commoncfg.Secret(o.APIKey)}},
		}}
	}
	return &rw
}

var localAddrRe = `(?:localhost|127\.0\.0\.1|\[::1\]):(\d+)`

// localInstanceRelabelConfig replaces the instance of targets scraped over the loopback interface
// (localhost:9100) with <hostname>:<port>, so that the instance is unique across nodes.
// It only applies if no instance label was set explicitly.
func localInstanceRelabelConfig(hostname string) *relabel.Config {
	return &relabel.Config{
		SourceLabels: model.LabelNames{model.InstanceLabel, model.AddressLabel},
		Separator:    ";",
		Regex:        relabel.MustNewRegexp(";" + localAddrRe),
		TargetLabel:  model.InstanceLabel,
		Replacement:  escapeReplacement(hostname) + ":$1",
		Action:       relabel.Replace,
	}
}

func escapeReplacement(s string) string {
	return strings.ReplaceAll(s, "$", "$$")
}

func dockerLabel(name string) model.LabelName {
	return model.LabelName(dockerLabelPrefix + sanitizeLabelName(name))
}

var invalidLabelCharRe = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func sanitizeLabelName(name string) string {
	return invalidLabelCharRe.ReplaceAllString(name, "_")
}

// DockerScrapeConfig returns the scrape config of the containers labeled with prometheus.io/scrape=true.
//
// Container labels:
//   - prometheus.io/scrape: "true" enables scraping
//   - prometheus.io/port: the port to scrape (by default each exposed TCP port, or 80)
//   - prometheus.io/path: the metrics path (default /metrics)
//   - prometheus.io/scheme: http (default) or https
//   - prometheus.io/job: the job label (default: the Compose service or the container name)
//
// Containers on bridge networks are scraped by their IP on the (first) network,
// containers on the host network at 127.0.0.1:<port>.
func DockerScrapeConfig(dockerHost, hostname string, composeGrouping bool) *config.ScrapeConfig {
	sd := moby.DefaultDockerSDConfig
	sd.Host = dockerHost
	sd.HostNetworkingHost = "127.0.0.1"
	sd.RefreshInterval = model.Duration(dockerRefreshInterval)
	sd.Filters = []moby.Filter{{Name: "label", Values: []string{dockerScrapeLabel + "=true"}}}

	sc := config.DefaultScrapeConfig
	sc.JobName = DockerJobName
	sc.HTTPClientConfig = commoncfg.DefaultHTTPClientConfig
	sc.ServiceDiscoveryConfigs = discovery.Configs{&sd}
	sc.RelabelConfigs = DockerRelabelConfigs(hostname, composeGrouping)
	return &sc
}

// DockerRelabelConfigs maps the Docker SD meta labels to the target address, path, scheme and labels.
func DockerRelabelConfigs(hostname string, composeGrouping bool) []*relabel.Config {
	const (
		containerName = model.MetaLabelPrefix + "docker_container_name"
		networkMode   = model.MetaLabelPrefix + "docker_container_network_mode"
		networkIP     = model.MetaLabelPrefix + "docker_network_ip"
	)
	var (
		port    = dockerLabel("prometheus.io/port")
		project = dockerLabel("com.docker.compose.project")
		service = dockerLabel("com.docker.compose.service")
		number  = dockerLabel("com.docker.compose.container-number")
		oneoff  = dockerLabel("com.docker.compose.oneoff")
	)
	host := escapeReplacement(hostname)
	replace := func(target string, regex string, replacement string, source ...model.LabelName) *relabel.Config {
		return &relabel.Config{
			SourceLabels: source,
			Separator:    ";",
			Regex:        relabel.MustNewRegexp(regex),
			TargetLabel:  target,
			Replacement:  replacement,
			Action:       relabel.Replace,
		}
	}
	rcs := []*relabel.Config{
		{
			SourceLabels: model.LabelNames{dockerLabel(dockerScrapeLabel)},
			Regex:        relabel.MustNewRegexp("true"),
			Action:       relabel.Keep,
		},
		{
			SourceLabels: model.LabelNames{dockerLabel("shards.ignore")},
			Regex:        relabel.MustNewRegexp("true"),
			Action:       relabel.Drop,
		},

		// address: <container ip>:<port> on bridge networks, 127.0.0.1:<port> on the host network
		replace(model.AddressLabel, `([^;]+);(\d+)`, "$1:$2", networkIP, port),
		replace(model.AddressLabel, `host;(\d+)`, "127.0.0.1:$1", networkMode, port),
		replace(model.MetricsPathLabel, `(.+)`, "$1", dockerLabel("prometheus.io/path")),
		replace(model.SchemeLabel, `(https?)`, "$1", dockerLabel("prometheus.io/scheme")),

		replace("container_name", `/?(.+)`, "$1", containerName),
		replace("compose_project", `(.+)`, "$1", project),
		replace("compose_service", `(.+)`, "$1", service),

		// job: prometheus.io/job, the Compose service or the container name
		replace(model.JobLabel, `/?(.+)`, "$1", containerName),
		replace(model.JobLabel, `(.+)`, "$1", service),
		replace(model.JobLabel, `(.+)`, "$1", dockerLabel("prometheus.io/job")),

		// instance: <hostname>/<container name>:<port>, or <hostname>:<port> on the host network
		replace(model.InstanceLabel, `/?([^;]+);.*:(\d+)`, host+"/$1:$2", containerName, model.AddressLabel),
		replace(model.InstanceLabel, `host;.*:(\d+)`, host+":$1", networkMode, model.AddressLabel),

		// container_id: the id Coroot uses for the container (see containers/shards.go)
		replace("container_id", `/?(.+)`, "/docker/$1", containerName),
	}
	if composeGrouping {
		rcs = append(rcs,
			replace("container_id", `([^;/]+);([^;/]+);([^;/]*)`, "/swarm/$1/$2/$3", project, service, number),
			replace("container_id", `(/swarm/[^/]+/[^/]+/)`, "${1}1", "container_id"), // no container-number label
			replace("container_id", `(?i:true);([^;/]+);([^;/]+);/?.*[-_]([^-_;]+)`, "/swarm/$1/$2-run/$3", oneoff, project, service, containerName),
		)
	}
	return rcs
}
