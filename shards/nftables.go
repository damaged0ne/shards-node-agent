//go:build linux

package shards

import (
	"os"
	"sync"

	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var nftFamilies = map[nftables.TableFamily]string{
	nftables.TableFamilyINet:   "inet",
	nftables.TableFamilyIPv4:   "ip",
	nftables.TableFamilyIPv6:   "ip6",
	nftables.TableFamilyARP:    "arp",
	nftables.TableFamilyNetdev: "netdev",
	nftables.TableFamilyBridge: "bridge",
}

type nftLister interface {
	ListTables() ([]*nftables.Table, error)
	ListChains() ([]*nftables.Chain, error)
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	GetObjects(t *nftables.Table) ([]nftables.Obj, error)
}

type nftCollector struct {
	netnsPath string

	lock    sync.Mutex
	netns   *os.File
	lastErr string
	newConn func(netnsFd int) (nftLister, error)
}

func newNftCollector(netnsPath string) *nftCollector {
	return &nftCollector{
		netnsPath: netnsPath,
		newConn: func(fd int) (nftLister, error) {
			return nftables.New(nftables.WithNetNSFd(fd))
		},
	}
}

func (c *nftCollector) collect(ch chan<- prometheus.Metric) {
	c.lock.Lock()
	defer c.lock.Unlock()
	samples, err := c.fetch()
	if err != nil {
		// log only when the error changes to avoid flooding on hosts without nftables access
		if s := err.Error(); s != c.lastErr {
			klog.Warningln("nftables:", s)
			c.lastErr = s
		}
		return
	}
	c.lastErr = ""
	for _, s := range samples {
		ch <- s
	}
}

func (c *nftCollector) fetch() ([]prometheus.Metric, error) {
	if c.netns == nil {
		f, err := os.Open(c.netnsPath)
		if err != nil {
			return nil, err
		}
		c.netns = f
	}
	conn, err := c.newConn(int(c.netns.Fd()))
	if err != nil {
		return nil, err
	}
	return nftSamples(conn)
}

type nftRuleKey struct {
	family, table, chain, comment string
}

func nftSamples(conn nftLister) ([]prometheus.Metric, error) {
	var res []prometheus.Metric
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		objs, err := conn.GetObjects(t)
		if err != nil {
			return nil, err
		}
		family := nftFamilies[t.Family]
		for _, o := range objs {
			if cnt, ok := o.(*nftables.CounterObj); ok {
				res = append(res,
					metrics.Counter(metrics.ShardsNftCounterBytes, float64(cnt.Bytes), family, t.Name, cnt.Name),
					metrics.Counter(metrics.ShardsNftCounterPackets, float64(cnt.Packets), family, t.Name, cnt.Name),
				)
			}
		}
	}

	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}
	// rules sharing a comment within a chain are summed up, duplicate series would break the scrape
	rules := map[nftRuleKey]*expr.Counter{}
	var order []nftRuleKey
	for _, chain := range chains {
		if chain.Table == nil {
			continue
		}
		rs, err := conn.GetRules(chain.Table, chain)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			comment, ok := userdata.GetString(r.UserData, userdata.TypeComment)
			if !ok || comment == "" {
				continue
			}
			for _, e := range r.Exprs {
				cnt, ok := e.(*expr.Counter)
				if !ok {
					continue
				}
				k := nftRuleKey{family: nftFamilies[chain.Table.Family], table: chain.Table.Name, chain: chain.Name, comment: comment}
				if v := rules[k]; v != nil {
					v.Bytes += cnt.Bytes
					v.Packets += cnt.Packets
				} else {
					rules[k] = &expr.Counter{Bytes: cnt.Bytes, Packets: cnt.Packets}
					order = append(order, k)
				}
				break
			}
		}
	}
	for _, k := range order {
		v := rules[k]
		res = append(res,
			metrics.Counter(metrics.ShardsNftRuleBytes, float64(v.Bytes), k.family, k.table, k.chain, k.comment),
			metrics.Counter(metrics.ShardsNftRulePackets, float64(v.Packets), k.family, k.table, k.chain, k.comment),
		)
	}
	return res, nil
}
