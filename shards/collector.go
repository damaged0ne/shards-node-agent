//go:build linux

// Package shards contains host collectors added by the Shards fork.
package shards

import (
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	nft *nftCollector
	f2b *f2bCollector
}

func NewCollector() *Collector {
	c := &Collector{}
	if !*flags.DisableNftablesMonitoring {
		c.nft = newNftCollector(proc.HostPath("/proc/1/ns/net"))
	}
	if !*flags.DisableFail2banMonitoring {
		c.f2b = &f2bCollector{dbPath: proc.HostPath(*flags.Fail2banDB)}
	}
	return c
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.ShardsNftCounterBytes
	ch <- metrics.ShardsNftCounterPackets
	ch <- metrics.ShardsNftRuleBytes
	ch <- metrics.ShardsNftRulePackets
	ch <- metrics.ShardsF2bUp
	ch <- metrics.ShardsF2bBanned
	ch <- metrics.ShardsF2bBans1h
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if c.nft != nil {
		c.nft.collect(ch)
	}
	if c.f2b != nil {
		c.f2b.collect(ch)
	}
}
