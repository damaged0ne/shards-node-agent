package main

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/coroot-node-agent/shards/probes"
	"github.com/coroot/coroot-node-agent/shards/promagent"
	"github.com/coroot/coroot-node-agent/shards/relay"
	"github.com/prometheus/client_golang/prometheus"
	commoncfg "github.com/prometheus/common/config"
	"k8s.io/klog/v2"
)

// startShards starts the fork's Prometheus agent (scraping of local targets) and synthetic probes.
// It returns the gatherer to expose on /metrics and a function that stops them.
func startShards(registry *prometheus.Registry, registerer prometheus.Registerer, hostname string) (prometheus.Gatherer, func()) {
	var gatherer prometheus.Gatherer = registry
	var stops []func()

	if *flags.ProbeConfigFile != "" {
		cfg, err := probes.LoadFile(*flags.ProbeConfigFile, *flags.ScrapeInterval)
		if err != nil {
			klog.Exitln(err)
		}
		r := probes.NewRunner(cfg)
		if err = registerer.Register(r); err != nil {
			klog.Exitln(err)
		}
		r.Start()
		klog.Infof("running %d probe(s)", len(cfg.Probes))
		stops = append(stops, r.Stop)
	}

	if a, selfReg := startScraping(hostname); a != nil {
		// A few of the agent's internal metrics are pushed to Coroot with the node-agent's own metrics,
		// all of them are exposed on /metrics.
		registerer.MustRegister(relay.New(selfReg, func(name string) bool { return promagent.SelfMetrics[name] }))
		gatherer = prometheus.Gatherers{registry, relay.Filter(selfReg, func(name string) bool { return !promagent.SelfMetrics[name] })}
		stops = append(stops, a.Stop)
	}

	return gatherer, func() {
		var wg sync.WaitGroup
		for _, stop := range stops {
			wg.Add(1)
			go func() {
				defer wg.Done()
				stop()
			}()
		}
		wg.Wait()
	}
}

func startScraping(hostname string) (*promagent.Agent, *prometheus.Registry) {
	if *flags.DisableScraping {
		klog.Infoln("scraping is disabled")
		return nil, nil
	}
	dockerHost := ""
	if sock := proc.HostPath("/run/docker.sock"); fileExists(sock) {
		dockerHost = "unix://" + sock
	}
	switch {
	case dockerHost == "" && *flags.ScrapeConfigFile == "":
		klog.Infoln("scraping is disabled: no Docker socket and no --scrape-config-file")
		return nil, nil
	case *flags.MetricsEndpoint == nil && *flags.ScrapeConfigFile == "":
		klog.Infoln("scraping is disabled: no metrics endpoint")
		return nil, nil
	}
	o := promagent.Options{
		Hostname:           hostname,
		Endpoint:           *flags.MetricsEndpoint,
		APIKey:             *flags.ApiKey,
		CAFile:             *flags.CAFile,
		InsecureSkipVerify: *flags.InsecureSkipVerify,
		ScrapeInterval:     *flags.ScrapeInterval,
		ConfigFile:         *flags.ScrapeConfigFile,
		DockerHost:         dockerHost,
		ComposeGrouping:    *flags.ComposeGrouping,
	}
	var httpOpts []commoncfg.HTTPClientOption
	if dial, err := promagent.HostNetnsDialer(proc.Path(1, "ns", "net")); err != nil {
		klog.Warningln("failed to open the host network namespace, targets are scraped from the agent's namespace:", err)
	} else if dial != nil {
		httpOpts = append(httpOpts, commoncfg.WithDialContextFunc(dial))
	}
	reg := prometheus.NewRegistry()
	a, err := promagent.Start(o, filepath.Join(*flags.WalDir, "scrape"), reg, httpOpts...)
	if err != nil {
		klog.Exitln("failed to start scraping:", err)
	}
	return a, reg
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
