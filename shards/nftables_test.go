//go:build linux

package shards

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeNft struct {
	tables []*nftables.Table
	chains []*nftables.Chain
	rules  map[string][]*nftables.Rule
	objs   map[string][]nftables.Obj
}

func (f *fakeNft) ListTables() ([]*nftables.Table, error) { return f.tables, nil }
func (f *fakeNft) ListChains() ([]*nftables.Chain, error) { return f.chains, nil }
func (f *fakeNft) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	return f.rules[t.Name+"/"+c.Name], nil
}
func (f *fakeNft) GetObjects(t *nftables.Table) ([]nftables.Obj, error) { return f.objs[t.Name], nil }

func rule(comment string, exprs ...expr.Any) *nftables.Rule {
	r := &nftables.Rule{Exprs: exprs}
	if comment != "" {
		r.UserData = userdata.AppendString(nil, userdata.TypeComment, comment)
	}
	return r
}

func gaugeValue(t *testing.T, m prometheus.Metric) float64 {
	var d dto.Metric
	require.NoError(t, m.Write(&d))
	if d.Counter != nil {
		return d.Counter.GetValue()
	}
	return d.Gauge.GetValue()
}

func flatten(t *testing.T, ms []prometheus.Metric) map[string]float64 {
	res := map[string]float64{}
	for _, m := range ms {
		var d dto.Metric
		require.NoError(t, m.Write(&d))
		key := m.Desc().String()
		key = key[len(`Desc{fqName: "`):]
		key = key[:strings.Index(key, `"`)]
		for _, l := range d.Label {
			key += " " + l.GetName() + "=" + l.GetValue()
		}
		res[key] = gaugeValue(t, m)
	}
	return res
}

func TestNftSamples(t *testing.T) {
	filter := &nftables.Table{Name: "filter", Family: nftables.TableFamilyINet}
	input := &nftables.Chain{Name: "input", Table: filter}
	f := &fakeNft{
		tables: []*nftables.Table{filter},
		chains: []*nftables.Chain{input},
		objs: map[string][]nftables.Obj{
			"filter": {&nftables.CounterObj{Table: filter, Name: "ssh_in", Bytes: 100, Packets: 2}},
		},
		rules: map[string][]*nftables.Rule{
			"filter/input": {
				rule("drop invalid", &expr.Counter{Bytes: 10, Packets: 1}, &expr.Verdict{Kind: expr.VerdictDrop}),
				rule("drop invalid", &expr.Counter{Bytes: 5, Packets: 1}),   // same comment: summed
				rule("", &expr.Counter{Bytes: 999, Packets: 9}),             // no comment: skipped
				rule("no counter", &expr.Verdict{Kind: expr.VerdictAccept}), // no counter: skipped
			},
		},
	}
	ms, err := nftSamples(f)
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{
		"shards_nft_counter_bytes_total counter=ssh_in family=inet table=filter":                  100,
		"shards_nft_counter_packets_total counter=ssh_in family=inet table=filter":                2,
		"shards_nft_rule_bytes_total chain=input comment=drop invalid family=inet table=filter":   15,
		"shards_nft_rule_packets_total chain=input comment=drop invalid family=inet table=filter": 2,
	}, flatten(t, ms))
}
