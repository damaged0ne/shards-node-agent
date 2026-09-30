package probes

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "s3cr3t-t0ken-for-tests"

func TestLoad(t *testing.T) {
	cfg, err := Load([]byte(`
probes:
  - name: website
    type: http
    target: https://www.example.com/health
    interval: 30s
    timeout: 5s
    labels:
      team: web
    http:
      method: POST
      valid_status_codes: [200, 204]
      headers:
        X-Token: `+testSecret+`
      authorization:
        credentials: `+testSecret+`
      tls_config:
        insecure_skip_verify: true
      fail_if_body_not_matches_regexp: ["ok"]
  - name: db
    type: tcp
    target: 127.0.0.1:5432
  - name: gateway
    type: icmp
    target: 192.0.2.1
    interval: 5s
  - name: resolver
    type: dns
    target: 127.0.0.1:53
    dns:
      query_name: example.com
      query_type: A
`), 15*time.Second)
	require.NoError(t, err)
	require.Len(t, cfg.Probes, 4)

	web := cfg.Probes[0]
	assert.Equal(t, model.Duration(30*time.Second), web.Interval)
	assert.Equal(t, model.Duration(5*time.Second), web.Timeout)
	assert.Equal(t, "POST", web.HTTP.Method)
	assert.Equal(t, []int{200, 204}, web.HTTP.ValidStatusCodes)
	assert.True(t, web.HTTP.HTTPClientConfig.TLSConfig.InsecureSkipVerify)
	assert.True(t, web.HTTP.IPProtocolFallback)
	assert.Len(t, web.HTTP.FailIfBodyNotMatchesRegexp, 1)
	assert.Equal(t, map[string]string{"team": "web"}, web.Labels)

	db := cfg.Probes[1]
	assert.Equal(t, model.Duration(15*time.Second), db.Interval)
	assert.Equal(t, model.Duration(10*time.Second), db.Timeout)
	assert.True(t, db.TCP.IPProtocolFallback)

	gw := cfg.Probes[2]
	assert.Equal(t, model.Duration(5*time.Second), gw.Timeout)
	assert.Equal(t, 64, gw.ICMP.TTL)

	resolver := cfg.Probes[3]
	assert.Equal(t, "example.com", resolver.DNS.QueryName)
	assert.True(t, resolver.DNS.Recursion)

	// secrets are masked
	s := cfg.String()
	assert.NotContains(t, s, testSecret)
	assert.Contains(t, s, "www.example.com")
}

func TestLoadErrors(t *testing.T) {
	for name, content := range map[string]string{
		"no name":            "probes: [{type: http, target: http://example.com}]",
		"duplicate":          "probes: [{name: a, type: tcp, target: '127.0.0.1:1'}, {name: a, type: tcp, target: '127.0.0.1:2'}]",
		"unknown type":       "probes: [{name: a, type: ftp, target: example.com}]",
		"no target":          "probes: [{name: a, type: tcp}]",
		"no dns query":       "probes: [{name: a, type: dns, target: '127.0.0.1:53'}]",
		"timeout > interval": "probes: [{name: a, type: tcp, target: '127.0.0.1:1', interval: 5s, timeout: 10s}]",
		"reserved label":     "probes: [{name: a, type: tcp, target: '127.0.0.1:1', labels: {instance: x}}]",
		"invalid label":      "probes: [{name: a, type: tcp, target: '127.0.0.1:1', labels: {a-b: x}}]",
		"unknown field":      "probes: [{name: a, type: tcp, target: '127.0.0.1:1', foo: bar}]",
		"unknown http field": "probes: [{name: a, type: http, target: 'http://127.0.0.1', http: {foo: bar}}]",
	} {
		_, err := Load([]byte(content), 15*time.Second)
		assert.Error(t, err, name)
	}
}

func load(t *testing.T, content string) *Probe {
	cfg, err := Load([]byte(content), 15*time.Second)
	require.NoError(t, err)
	require.Len(t, cfg.Probes, 1)
	return cfg.Probes[0]
}

// values returns the metrics as "name{labels}" -> value.
func values(mfs []*dto.MetricFamily) map[string]float64 {
	res := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.Metric {
			var ls []string
			for _, l := range m.Label {
				ls = append(ls, l.GetName()+"="+l.GetValue())
			}
			res[mf.GetName()+"{"+strings.Join(ls, ",")+"}"] = m.GetGauge().GetValue()
		}
	}
	return res
}

func TestHTTPProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Token") != testSecret {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte("status: ok"))
		default:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	p := load(t, `
probes:
  - name: api
    type: http
    target: `+srv.URL+`/health
    labels: {team: core}
    http:
      headers: {X-Token: `+testSecret+`}
      fail_if_body_not_matches_regexp: ["status: ok"]
`)
	v := values(Run(context.Background(), p))
	labels := "instance=" + srv.URL + "/health,job=api,team=core"
	assert.Equal(t, 1.0, v["probe_success{"+labels+"}"])
	assert.Equal(t, 200.0, v["probe_http_status_code{"+labels+"}"])
	assert.Contains(t, v, "probe_duration_seconds{"+labels+"}")

	p.Target = srv.URL + "/other"
	v = values(Run(context.Background(), p))
	labels = "instance=" + srv.URL + "/other,job=api,team=core"
	assert.Equal(t, 0.0, v["probe_success{"+labels+"}"])
	assert.Equal(t, 503.0, v["probe_http_status_code{"+labels+"}"])

	// body regexp mismatch
	p = load(t, `
probes:
  - name: api
    type: http
    target: `+srv.URL+`/health
    http:
      headers: {X-Token: `+testSecret+`}
      fail_if_body_not_matches_regexp: ["status: degraded"]
`)
	v = values(Run(context.Background(), p))
	assert.Equal(t, 0.0, v["probe_success{instance="+srv.URL+"/health,job=api}"])
}

func TestHTTPSProbe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	p := load(t, `
probes:
  - name: tls
    type: http
    target: `+srv.URL+`
    http:
      tls_config: {insecure_skip_verify: true}
`)
	v := values(Run(context.Background(), p))
	labels := "{instance=" + srv.URL + ",job=tls}"
	assert.Equal(t, 1.0, v["probe_success"+labels])
	assert.Greater(t, v["probe_ssl_earliest_cert_expiry"+labels], float64(time.Now().Unix()))

	// the test certificate isn't trusted without insecure_skip_verify
	p = load(t, "probes: [{name: tls, type: http, target: '"+srv.URL+"'}]")
	v = values(Run(context.Background(), p))
	assert.Equal(t, 0.0, v["probe_success"+labels])
}

func TestTCPProbe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := l.Addr().String()
	p := load(t, "probes: [{name: db, type: tcp, target: '"+addr+"', timeout: 2s}]")
	v := values(Run(context.Background(), p))
	assert.Equal(t, 1.0, v["probe_success{instance="+addr+",job=db}"])

	_ = l.Close()
	v = values(Run(context.Background(), p))
	assert.Equal(t, 0.0, v["probe_success{instance="+addr+",job=db}"])
}

func TestDNSProbe(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "example.com." && r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR("example.com. 60 IN A 192.0.2.10")
			m.Answer = append(m.Answer, rr)
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	addr := pc.LocalAddr().String()

	p := load(t, `
probes:
  - name: resolver
    type: dns
    target: `+addr+`
    timeout: 2s
    dns:
      query_name: example.com
      query_type: A
      transport_protocol: udp
      preferred_ip_protocol: ip4
`)
	labels := "{instance=" + addr + ",job=resolver}"
	v := values(Run(context.Background(), p))
	assert.Equal(t, 1.0, v["probe_success"+labels])
	assert.Equal(t, 1.0, v["probe_dns_answer_rrs"+labels])

	p.DNS.QueryName = "missing.example.com"
	v = values(Run(context.Background(), p))
	assert.Equal(t, 0.0, v["probe_success"+labels])
}

func TestRunner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	cfg, err := Load([]byte("probes: [{name: web, type: http, target: '"+srv.URL+"', interval: 1s}]"), time.Second)
	require.NoError(t, err)
	r := NewRunner(cfg)

	reg := prometheus.NewRegistry()
	require.NoError(t, prometheus.WrapRegistererWith(prometheus.Labels{"machine_id": "m1"}, reg).Register(r))
	r.Start()
	defer r.Stop()

	require.Eventually(t, func() bool {
		mfs, err := reg.Gather()
		require.NoError(t, err)
		return values(mfs)["probe_success{instance="+srv.URL+",job=web,machine_id=m1}"] == 1
	}, 10*time.Second, 50*time.Millisecond)
}
