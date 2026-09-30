package promagent

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery/file"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/scrape"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAPIKey   = "test-api-key-0123456789"
	testSecret   = "s3cr3t-p4ssw0rd-for-tests"
	testHostname = "node-1.example.com"
)

func testOptions(t *testing.T) Options {
	u, err := url.Parse("http://coroot.example.com:8080/v1/metrics")
	require.NoError(t, err)
	return Options{
		Hostname:        testHostname,
		Endpoint:        u,
		APIKey:          testAPIKey,
		ScrapeInterval:  15 * time.Second,
		DockerHost:      "unix:///proc/1/root/run/docker.sock",
		ComposeGrouping: true,
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0600))
	return p
}

func TestBuildConfigDefaults(t *testing.T) {
	cfg, err := BuildConfig(testOptions(t))
	require.NoError(t, err)

	assert.Equal(t, model.Duration(15*time.Second), cfg.GlobalConfig.ScrapeInterval)
	assert.Equal(t, model.Duration(10*time.Second), cfg.GlobalConfig.ScrapeTimeout)
	assert.Equal(t, labels.FromStrings("host", testHostname), cfg.GlobalConfig.ExternalLabels)

	require.Len(t, cfg.ScrapeConfigs, 1)
	sc := cfg.ScrapeConfigs[0]
	assert.Equal(t, DockerJobName, sc.JobName)
	assert.Equal(t, model.Duration(15*time.Second), sc.ScrapeInterval)
	assert.Equal(t, "/metrics", sc.MetricsPath)

	require.Len(t, cfg.RemoteWriteConfigs, 1)
	rw := cfg.RemoteWriteConfigs[0]
	assert.Equal(t, CorootRemoteWriteName, rw.Name)
	assert.Equal(t, "http://coroot.example.com:8080/v1/metrics", rw.URL.String())
	assert.True(t, rw.HTTPClientConfig.ProxyConfig.ProxyFromEnvironment)
	require.NotNil(t, rw.HTTPClientConfig.HTTPHeaders)
	assert.Equal(t, testAPIKey, string(rw.HTTPClientConfig.HTTPHeaders.Headers["X-Api-Key"].Secrets[0]))
	assert.NotContains(t, cfg.String(), testAPIKey)

	// short scrape intervals shorten the default timeout
	o := testOptions(t)
	o.ScrapeInterval = 5 * time.Second
	cfg, err = BuildConfig(o)
	require.NoError(t, err)
	assert.Equal(t, model.Duration(5*time.Second), cfg.ScrapeConfigs[0].ScrapeTimeout)

	// no endpoint and no docker
	cfg, err = BuildConfig(Options{Hostname: testHostname, ScrapeInterval: time.Minute})
	require.NoError(t, err)
	assert.Empty(t, cfg.ScrapeConfigs)
	assert.Empty(t, cfg.RemoteWriteConfigs)
}

func TestBuildConfigFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "targets.json", `[{"targets": ["localhost:9323"], "labels": {"env": "test"}}]`)
	o := testOptions(t)
	o.ConfigFile = writeFile(t, dir, "prometheus.yml", `
global:
  external_labels:
    dc: dc1
scrape_configs:
  - job_name: node
    static_configs:
      - targets: ["localhost:9100"]
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: go_.*
        action: drop
  - job_name: docker-exporter
    scrape_interval: 1m
    scrape_timeout: 20s
    basic_auth:
      username: prometheus
      password: `+testSecret+`
    file_sd_configs:
      - files: [targets.json]
remote_write:
  - url: https://user:`+testSecret+`@backup.example.com/api/v1/write
    headers:
      X-Scope-OrgID: `+testSecret+`
`)
	cfg, err := BuildConfig(o)
	require.NoError(t, err)

	assert.Equal(t, labels.FromStrings("dc", "dc1", "host", testHostname), cfg.GlobalConfig.ExternalLabels)
	assert.Equal(t, model.Duration(15*time.Second), cfg.GlobalConfig.ScrapeInterval)

	require.Len(t, cfg.ScrapeConfigs, 3)
	node, dexp, docker := cfg.ScrapeConfigs[0], cfg.ScrapeConfigs[1], cfg.ScrapeConfigs[2]
	assert.Equal(t, "node", node.JobName)
	assert.Equal(t, model.Duration(15*time.Second), node.ScrapeInterval)
	assert.Len(t, node.MetricRelabelConfigs, 1)
	assert.Equal(t, "docker-exporter", dexp.JobName)
	assert.Equal(t, model.Duration(time.Minute), dexp.ScrapeInterval)
	assert.Equal(t, model.Duration(20*time.Second), dexp.ScrapeTimeout)
	require.Len(t, dexp.ServiceDiscoveryConfigs, 1)
	assert.Equal(t, []string{filepath.Join(dir, "targets.json")}, dexp.ServiceDiscoveryConfigs[0].(*file.SDConfig).Files)
	assert.Equal(t, DockerJobName, docker.JobName)

	require.Len(t, cfg.RemoteWriteConfigs, 2)
	assert.Equal(t, CorootRemoteWriteName, cfg.RemoteWriteConfigs[0].Name)
	backup := cfg.RemoteWriteConfigs[1]
	assert.Empty(t, backup.Headers)
	assert.Equal(t, testSecret, string(backup.HTTPClientConfig.HTTPHeaders.Headers["X-Scope-OrgID"].Secrets[0]))

	// secrets are masked whenever the config is marshaled
	s := cfg.String()
	assert.NotContains(t, s, testSecret)
	assert.NotContains(t, s, testAPIKey)
	assert.Contains(t, s, "backup.example.com")

	// the global scrape_interval of the file wins over the option
	o.ConfigFile = writeFile(t, dir, "prometheus2.yml", "global:\n  scrape_interval: 30s\nscrape_configs:\n  - job_name: node\n    static_configs: [{targets: ['localhost:9100']}]\n")
	cfg, err = BuildConfig(o)
	require.NoError(t, err)
	assert.Equal(t, model.Duration(30*time.Second), cfg.ScrapeConfigs[0].ScrapeInterval)
}

func TestBuildConfigErrors(t *testing.T) {
	dir := t.TempDir()
	o := testOptions(t)
	for name, content := range map[string]string{
		"reserved job":       "scrape_configs:\n  - job_name: docker\n    static_configs: [{targets: ['localhost:9100']}]\n",
		"reserved rw name":   "remote_write:\n  - name: coroot\n    url: http://example.com/write\n",
		"rule files":         "rule_files: [rules.yml]\n",
		"remote read":        "remote_read:\n  - url: http://example.com/read\n",
		"unknown field":      "scrape_configs:\n  - job_name: x\n    foo: bar\n",
		"invalid yaml":       "scrape_configs: [",
		"timeout > interval": "scrape_configs:\n  - job_name: x\n    scrape_interval: 5s\n    scrape_timeout: 10s\n",
	} {
		o.ConfigFile = writeFile(t, dir, "prometheus.yml", content)
		_, err := BuildConfig(o)
		assert.Error(t, err, name)
	}
	o.ConfigFile = filepath.Join(dir, "missing.yml")
	_, err := BuildConfig(o)
	assert.Error(t, err)
}

// populate applies the target relabeling of the scrape config to a discovered target.
func populate(t *testing.T, sc *config.ScrapeConfig, target model.LabelSet) map[string]string {
	res, err := scrape.PopulateLabels(labels.NewBuilder(labels.EmptyLabels()), sc, target, nil)
	require.NoError(t, err)
	if res.IsEmpty() {
		return nil
	}
	return res.Map()
}

func TestLocalInstance(t *testing.T) {
	o := testOptions(t)
	o.DockerHost = ""
	o.ConfigFile = writeFile(t, t.TempDir(), "prometheus.yml", `
scrape_configs:
  - job_name: node
    static_configs: [{targets: ['localhost:9100']}]
`)
	cfg, err := BuildConfig(o)
	require.NoError(t, err)
	sc := cfg.ScrapeConfigs[0]

	for addr, instance := range map[string]string{
		"localhost:9100":   testHostname + ":9100",
		"127.0.0.1:9323":   testHostname + ":9323",
		"[::1]:8080":       testHostname + ":8080",
		"10.0.0.5:9100":    "10.0.0.5:9100",
		"db.example.com:1": "db.example.com:1",
	} {
		ls := populate(t, sc, model.LabelSet{model.AddressLabel: model.LabelValue(addr)})
		assert.Equal(t, instance, ls["instance"], addr)
		assert.Equal(t, addr, ls["__address__"])
	}
	// an explicit instance is kept
	ls := populate(t, sc, model.LabelSet{model.AddressLabel: "localhost:9100", model.InstanceLabel: "node-exporter"})
	assert.Equal(t, "node-exporter", ls["instance"])
}

func dockerTarget(name, networkMode, ip, privatePort string, containerLabels map[string]string) model.LabelSet {
	ls := model.LabelSet{
		"__meta_docker_container_id":           "0123456789abcdef",
		"__meta_docker_container_name":         model.LabelValue("/" + name),
		"__meta_docker_container_network_mode": model.LabelValue(networkMode),
		"__meta_docker_network_ip":             model.LabelValue(ip),
		"__meta_docker_network_name":           "net",
	}
	addr := ip + ":80"
	if privatePort != "" {
		ls["__meta_docker_port_private"] = model.LabelValue(privatePort)
		addr = ip + ":" + privatePort
	}
	if networkMode == "host" {
		addr = "127.0.0.1"
	}
	ls[model.AddressLabel] = model.LabelValue(addr)
	for k, v := range containerLabels {
		ls[dockerLabel(k)] = model.LabelValue(v)
	}
	return ls
}

func compose(project, service, number string, extra map[string]string) map[string]string {
	res := map[string]string{
		"prometheus.io/scrape":       "true",
		"com.docker.compose.project": project,
		"com.docker.compose.service": service,
	}
	if number != "" {
		res["com.docker.compose.container-number"] = number
	}
	for k, v := range extra {
		res[k] = v
	}
	return res
}

func TestDockerRelabel(t *testing.T) {
	sc := DockerScrapeConfig("unix:///run/docker.sock", testHostname, true)
	require.NoError(t, sc.Validate(config.DefaultGlobalConfig))

	// bridge network, Compose, explicit port
	ls := populate(t, sc, dockerTarget("shop-api-2", "shop_default", "172.18.0.5", "8080",
		compose("shop", "api", "2", map[string]string{"prometheus.io/port": "9102"})))
	assert.Equal(t, map[string]string{
		"__address__":         "172.18.0.5:9102",
		"__metrics_path__":    "/metrics",
		"__scheme__":          "http",
		"__scrape_interval__": "1m",
		"__scrape_timeout__":  "10s",
		"job":                 "api",
		"instance":            testHostname + "/shop-api-2:9102",
		"container_name":      "shop-api-2",
		"compose_project":     "shop",
		"compose_service":     "api",
		"container_id":        "/swarm/shop/api/2",
	}, ls)

	// host network, path, scheme and job overrides, no container-number label
	ls = populate(t, sc, dockerTarget("shop-worker-1", "host", "", "",
		compose("shop", "worker", "", map[string]string{
			"prometheus.io/port":   "9200",
			"prometheus.io/path":   "/internal/metrics",
			"prometheus.io/scheme": "https",
			"prometheus.io/job":    "shop-worker",
		})))
	assert.Equal(t, "127.0.0.1:9200", ls["__address__"])
	assert.Equal(t, "/internal/metrics", ls["__metrics_path__"])
	assert.Equal(t, "https", ls["__scheme__"])
	assert.Equal(t, "shop-worker", ls["job"])
	assert.Equal(t, testHostname+":9200", ls["instance"])
	assert.Equal(t, "/swarm/shop/worker/1", ls["container_id"])

	// no port label: the exposed port is used
	ls = populate(t, sc, dockerTarget("redis", "bridge", "172.17.0.3", "9121", map[string]string{"prometheus.io/scrape": "true"}))
	assert.Equal(t, "172.17.0.3:9121", ls["__address__"])
	assert.Equal(t, "redis", ls["job"])
	assert.Equal(t, testHostname+"/redis:9121", ls["instance"])
	assert.Equal(t, "/docker/redis", ls["container_id"])
	assert.Empty(t, ls["compose_project"])

	// one-off `docker compose run` container
	ls = populate(t, sc, dockerTarget("shop-migrate-run-3f2a9c1b", "shop_default", "172.18.0.9", "",
		compose("shop", "migrate", "1", map[string]string{"com.docker.compose.oneoff": "True", "prometheus.io/port": "9000"})))
	assert.Equal(t, "/swarm/shop/migrate-run/3f2a9c1b", ls["container_id"])

	// not labeled, disabled, or ignored containers are dropped
	assert.Nil(t, populate(t, sc, dockerTarget("a", "bridge", "172.17.0.4", "80", nil)))
	assert.Nil(t, populate(t, sc, dockerTarget("b", "bridge", "172.17.0.4", "80", map[string]string{"prometheus.io/scrape": "false"})))
	assert.Nil(t, populate(t, sc, dockerTarget("c", "bridge", "172.17.0.4", "80", map[string]string{"prometheus.io/scrape": "true", "shards.ignore": "true"})))

	// without Compose grouping, Coroot ids Compose containers by name
	sc = DockerScrapeConfig("unix:///run/docker.sock", testHostname, false)
	require.NoError(t, sc.Validate(config.DefaultGlobalConfig))
	ls = populate(t, sc, dockerTarget("shop-api-2", "shop_default", "172.18.0.5", "8080", compose("shop", "api", "2", nil)))
	assert.Equal(t, "/docker/shop-api-2", ls["container_id"])
}

func TestRedact(t *testing.T) {
	assert.Equal(t, `url=https://xxxxx@example.com/write err="Post \"http://xxxxx@example.com\": EOF"`,
		Redact(`url=https://user:`+testSecret+`@example.com/write err="Post \"http://`+testSecret+`@example.com\": EOF"`))
	assert.Equal(t, "http://example.com:9100/metrics", Redact("http://example.com:9100/metrics"))
}
