# Coroot-node-agent

[![Go Report Card](https://goreportcard.com/badge/github.com/coroot/coroot-node-agent)](https://goreportcard.com/report/github.com/coroot/coroot-node-agent)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The agent gathers metrics related to a node and the containers running on it, and it exposes them in the Prometheus format.

It uses eBPF to track container related events such as TCP connects, so the minimum supported Linux kernel version is 5.1.
The kernel must also be built with `CONFIG_BPF_EVENTS=y` (kprobe and tracepoint BPF programs); some embedded and vendor kernels disable it.

<img src="https://coroot.com/static/img/blog/ebpf.svg" width="800" />

## Shards fork additions

Fork-specific code lives in `*shards*.go` files and the `shards/` packages to keep upstream merges simple.

| Flag / metric | Description |
|---|---|
| `--hostname-override` (`HOSTNAME_OVERRIDE`) | Hostname reported in `node_info`, logs, traces and profiles instead of the host's UTS hostname |
| `shards_fs_size_bytes`, `shards_fs_avail_bytes` | Filesystem size / space available to non-root users, per host mount (`mount`, `device`, `fs`) |
| `shards_fs_files`, `shards_fs_files_free` | Total / free inodes per host mount |
| `shards_fs_readonly` | 1 if the mount is read-only |
| `shards_load1`, `shards_load5`, `shards_load15` | Load averages |
| `--compose-grouping` (default on, `COMPOSE_GROUPING`) | Docker Compose containers are reported as `/swarm/<project>/<service>/<number>`, so Coroot shows one application per service (namespace = project) instead of one per replica. One-off `docker compose run` containers become `/swarm/<project>/<service>-run/<suffix>`. `--no-compose-grouping` restores `/docker/<name>` |
| `shards.ignore=true` Docker label | The container isn't monitored |
| `--container-labels` (`CONTAINER_LABELS`) | Docker labels exported by `shards_container_labels{container_id,label_<name>...}` (names sanitized, e.g. `team` -> `label_team`) |
| `shards_container_state{container_id,state}` | Docker state: `running`, `exited`, `restarting`, `paused`, `created`, `dead`, `removing` (includes stopped containers) |
| `shards_container_health{container_id,status}` | Docker healthcheck status (`healthy`, `unhealthy`, `starting`) of running containers with a healthcheck |
| `shards_container_exit_code`, `shards_container_oom_killed` | Result of the last run of a container that isn't running |
| `shards_container_started_seconds`, `shards_container_finished_seconds` | Unix time of the last start / finish |
| `shards_container_docker_restarts`, `shards_container_restart_policy{policy}` | dockerd restart count and restart policy |
| `shards_container_image_info{container_id,image,image_id,version,revision}` | Image, with version and revision from the `org.opencontainers.image.*` labels |
| `shards_compose_info{container_id,project,service}` | Docker Compose project and service of the container |
| `shards_container_created_seconds` | Unix time the container was created. Compose recreates containers only on image or config changes, restarts and reboots keep it |
| `shards_release_window{container_id,version,image_id}` | Present during the release window after a container is (re)created, the value is the seconds left. `--release-window` (default `30m`, `RELEASE_WINDOW`) sets the length, the `shards.release-window` label overrides it per service (`"2h"`, `"0"` disables). One-off `compose run` containers are excluded. `version` comes from the OCI version label, then the image tag, then the short image id |
| `shards_nft_counter_{bytes,packets}_total{family,table,counter}` | Named nftables counters, read over netlink in the host network namespace |
| `shards_nft_rule_{bytes,packets}_total{family,table,chain,comment}` | nftables rules that have both a `counter` and a `comment` (rules sharing a comment in a chain are summed) |
| `shards_f2b_up` | 1 if the fail2ban database could be read (absent when fail2ban isn't installed) |
| `shards_f2b_banned{jail}`, `shards_f2b_bans_1h{jail}` | Currently banned IPs and bans issued during the last hour, per enabled jail (fail2ban >= 0.11) |
| `--disable-nftables-monitoring`, `--disable-fail2ban-monitoring`, `--fail2ban-db` | Collector switches and the fail2ban database path on the host (default `/var/lib/fail2ban/fail2ban.sqlite3`) |
| `--disable-scraping` (`DISABLE_SCRAPING`) | Turns off the [local Prometheus agent](#scraping-local-prometheus-targets). Scraping is on when `--metrics-endpoint` (or `--collector-endpoint`) is set and the Docker socket (`/run/docker.sock` on the host) exists, or when `--scrape-config-file` is set |
| `--scrape-config-file` (`SCRAPE_CONFIG_FILE`) | Prometheus configuration file whose `scrape_configs` are scraped too and whose `remote_write` entries are additional destinations |
| `prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path`, `prometheus.io/scheme`, `prometheus.io/job` Docker labels | Scrape the container's metrics, see [below](#docker-containers) |
| `host`, `instance`, `job`, `container_name`, `compose_project`, `compose_service`, `container_id` labels | Added to the scraped series, see [below](#labels) |
| `prometheus_remote_storage_*`, `prometheus_sd_*`, `prometheus_target_*`, `prometheus_agent_*`, `prometheus_tsdb_wal_*` | Internal metrics of the scrape manager, service discovery, remote write queues and WAL on `/metrics`. Only `prometheus_remote_storage_samples_{total,failed_total,retried_total,dropped_total,pending}`, `prometheus_remote_storage_{highest_timestamp_in_seconds,queue_highest_sent_timestamp_seconds,shards}`, `prometheus_sd_discovered_targets` and `prometheus_target_scrape_pool_targets` are also pushed to Coroot |
| `--probe-config-file` (`PROBE_CONFIG_FILE`) | Synthetic probes, see [below](#synthetic-probes) |
| `probe_success`, `probe_duration_seconds`, `probe_http_*`, `probe_ssl_earliest_cert_expiry`, `probe_dns_*`, `probe_icmp_*`, ... `{job=<probe>,instance=<target>}` | blackbox_exporter metrics of the probes |

### Scraping local Prometheus targets

The agent also works as a local Prometheus agent: it discovers and scrapes the Prometheus targets on its node and
remote-writes the samples to the same Coroot endpoint as its own metrics (`--metrics-endpoint`, with `--api-key`,
`--ca-file`, `--insecure-skip-verify` and the `HTTPS_PROXY`/`NO_PROXY` environment). Samples are buffered in an
agent-mode WAL in `<wal-dir>/scrape` (up to 4h while Coroot is unreachable). The default scrape interval is `--scrape-interval`.

Targets are scraped from the host network namespace (the agent doesn't need `network_mode: host`), so `127.0.0.1`
is the host's loopback and containers are reachable at their bridge network IPs.

#### Docker containers

Containers with the `prometheus.io/scrape: "true"` label are discovered through the Docker API:

| Label | Default | |
|---|---|---|
| `prometheus.io/scrape` | | `"true"` to scrape the container |
| `prometheus.io/port` | every exposed TCP port (or 80) | Port of the metrics endpoint. Required for containers on the host network |
| `prometheus.io/path` | `/metrics` | |
| `prometheus.io/scheme` | `http` | `http` or `https` |
| `prometheus.io/job` | the Compose service, or the container name | Value of the `job` label |

Containers on bridge networks are scraped at `<container IP on its first network>:<port>`, containers on the host
network at `127.0.0.1:<port>`. Containers with `shards.ignore=true` are skipped.

```yaml
services:
  api:
    image: example/api
    labels:
      prometheus.io/scrape: "true"
      prometheus.io/port: "9102"
      prometheus.io/path: /internal/metrics
  worker:
    image: example/worker
    network_mode: host
    labels:
      prometheus.io/scrape: "true"
      prometheus.io/port: "9200"
```

#### Labels

* `host`: the hostname (`--hostname-override` if set), added to every series as an external label (it doesn't override a `host` label exposed by the target)
* `instance`: `<hostname>/<container name>:<port>` for containers on bridge networks, `<hostname>:<port>` for containers on the host network,
  and `<hostname>:<port>` for targets of `--scrape-config-file` jobs addressed as `localhost`, `127.0.0.1` or `[::1]` (unless the job sets `instance`)
* `job`: see `prometheus.io/job`
* `container_name`, `compose_project`, `compose_service` (from the `com.docker.compose.*` labels)
* `container_id`: the id of the container in Coroot: `/swarm/<project>/<service>/<number>` for Compose containers
  (`/swarm/<project>/<service>-run/<suffix>` for `docker compose run`), `/docker/<name>` otherwise or with `--no-compose-grouping`.
  Swarm, Nomad and Kubernetes ids aren't computed

#### Scrape config file

`--scrape-config-file` takes a standard Prometheus configuration (`global`, `scrape_configs` with `static_configs`,
`file_sd_configs`, `dns_sd_configs`, `http_sd_configs`, `relabel_configs`, `metric_relabel_configs`, per-job
`scrape_interval`/`scrape_timeout`, authentication, `scrape_config_files`, and `remote_write`), so the jobs of a central
Prometheus can be moved to the agents unchanged. Relative paths are resolved from the file's directory, the file and
the `file_sd` files must be mounted into the agent's container. `remote_write` entries are *additional* destinations
(Coroot is always the first one); `alerting`, `rule_files` and `remote_read` aren't allowed. The job name `docker` is reserved.

```yaml
# /etc/coroot-node-agent/prometheus.yml
global:
  scrape_interval: 30s          # default: --scrape-interval
scrape_configs:
  - job_name: node-exporter
    static_configs:
      - targets: ["localhost:9100"]   # instance=<hostname>:9100
  - job_name: docker-exporter
    file_sd_configs:
      - files: ["targets/docker-exporter.json"]
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: go_.*
        action: drop
remote_write:                   # optional, in addition to Coroot
  - url: https://prometheus.example.com/api/v1/write
    basic_auth:
      username: agent
      password_file: /etc/coroot-node-agent/rw-password
```

```yaml
services:
  coroot-node-agent:
    image: ghcr.io/coroot/coroot-node-agent
    privileged: true
    pid: host
    volumes:
      - /sys/kernel/tracing:/sys/kernel/tracing
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/cgroup:/host/sys/fs/cgroup
      - ./prometheus.yml:/etc/coroot-node-agent/prometheus.yml:ro
      - ./targets:/etc/coroot-node-agent/targets:ro
      - ./probes.yml:/etc/coroot-node-agent/probes.yml:ro
    command:
      - --cgroupfs-root=/host/sys/fs/cgroup
      - --collector-endpoint=https://coroot.example.com
      - --scrape-config-file=/etc/coroot-node-agent/prometheus.yml
      - --probe-config-file=/etc/coroot-node-agent/probes.yml
    environment:
      API_KEY: ${COROOT_API_KEY}
```

Credentials in the configuration (`basic_auth`, `authorization`, `oauth2`, remote_write `headers`) are treated as
secrets: they are never logged or exported, and URLs are logged without their user info. The Coroot API key is only
sent to Coroot, never to the scraped targets.

#### Synthetic probes

`--probe-config-file` replaces a blackbox_exporter: the probes run on the node with the blackbox_exporter probers,
so the metrics have the same names (`probe_success`, `probe_duration_seconds`, `probe_http_status_code`,
`probe_ssl_earliest_cert_expiry`, `probe_dns_lookup_time_seconds`, ...). They are labeled with `job=<probe name>`,
`instance=<target>` and the probe's `labels`, and pushed with the agent's own metrics. The `http`, `tcp`, `icmp`
and `dns` sections take the options of the corresponding sections of a
[blackbox_exporter module](https://github.com/prometheus/blackbox_exporter/blob/master/CONFIGURATION.md).
`interval` defaults to `--scrape-interval`, `timeout` to 10s (at most the interval). Probes run from the agent's
network namespace and don't use the proxy environment unless `http.proxy_from_environment: true`.

```yaml
probes:
  - name: website
    type: http
    target: https://www.example.com/health
    interval: 30s
    timeout: 5s
    labels:
      team: web
    http:
      method: GET
      valid_status_codes: [200]
      headers:
        Accept: application/json
      authorization:
        credentials_file: /etc/coroot-node-agent/probe-token
      tls_config:
        insecure_skip_verify: false
      fail_if_body_not_matches_regexp: ['"status":\s*"ok"']
  - name: postgres
    type: tcp
    target: 127.0.0.1:5432
  - name: gateway
    type: icmp
    target: 192.0.2.1
    icmp:
      preferred_ip_protocol: ip4
  - name: resolver
    type: dns
    target: 127.0.0.1:53
    dns:
      query_name: example.com
      query_type: A
```

## Features

### TCP connection tracing

To provide visibility into the relationships between services, the agent traces containers TCP events, such as *connect()* and *listen()*.

Exported metrics are useful for:
* Obtaining an actual map of inter-service communications. It doesn't require integration of distributed tracing frameworks into your code.
* Detecting connections errors from one service to another.
* Measuring network latency between containers, nodes and availability zones.

Related blog posts:
 * [Building a service map using eBPF](https://coroot.com/blog/building-a-service-map-using-ebpf)
 * [How ping measures network round-trip time accurately using SO_TIMESTAMPING](https://coroot.com/blog/how-to-ping)
 * [The current state of eBPF portability](https://coroot.com/blog/ebpf-portability)
### Log patterns extraction

Log management is usually quite expensive. In most cases, you do not need to analyze each event individually.
It is enough to extract recurring patterns and the number of the related events.

This approach drastically reduces the amount of data required for express log analysis.

The agent discovers container logs and parses them right on the node.

At the moment the following sources are supported:
* Direct logging to files in */var/log/*
* Journald
* Dockerd (JSON file driver)
* Containerd (CRI logs)

To learn more about automated log clustering, check out the blog post "[Mining metrics from unstructured logs](https://coroot.com/blog/mining-logs-from-unstructured-logs)".

### Delay accounting

[Delay accounting](https://www.kernel.org/doc/html/latest/accounting/delay-accounting.html) allows engineers to accurately
identify situations where a container is experiencing a lack of CPU time or waiting for I/O.

The agent gathers per-process counters through [Netlink](https://man7.org/linux/man-pages/man7/netlink.7.html) and aggregates them into per-container metrics:
* [container_resources_cpu_delay_seconds_total](https://docs.coroot.com/metrics/node-agent#container_resources_cpu_delay_seconds_total)
* [container_resources_disk_delay_seconds_total](https://docs.coroot.com/metrics/node-agent#container_resources_disk_delay_seconds_total)


<img src="https://coroot.com/static/img/blog/delay_accounting_aggregation.svg" width="800" />

Related blog posts:
* [Delay accounting: an underrated feature of the Linux kernel](https://coroot.com/blog/linux-delay-accounting)


### Out-of-memory events tracing

The [container_oom_kills_total](https://docs.coroot.com/metrics/node-agent#container_oom_kills_total) metric shows that a container has been terminated by the OOM killer.

### Instance meta information

If a node is a cloud instance, the agent identifies a cloud provider and collects additional information using the related metadata services.

Supported cloud providers: [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html), [GCP](https://cloud.google.com/compute/docs/metadata/overview), [Azure](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service?tabs=linux), [Hetzner](https://docs.hetzner.cloud/#server-metadata)

Collected info:
* AccountID
* InstanceID
* Instance/machine type
* Region
* AvailabilityZone
* AvailabilityZoneId (AWS only)
* LifeCycle: on-demand/spot (AWS and GCP only)
* Private & Public IP addresses

Related blog posts:
* [Gathering cloud instance metadata in AWS, GCP and Azure](https://coroot.com/blog/cloud-metadata)

## Installation

Follow the Coroot [documentation](https://docs.coroot.com/)

## Metrics

The collected metrics are described [here](https://docs.coroot.com/metrics/node-agent).

## Coroot

The best way to turn metrics to answers about app issues is to use [Coroot](https://github.com/coroot/coroot) - a zero-instrumentation observability tool for microservice architectures. 

A live demo of Coroot is available at [demo.coroot.com](https://demo.coroot.com)

## Contributing
To start contributing, check out our [Contributing Guide](https://github.com/coroot/coroot-node-agent/blob/main/CONTRIBUTING.md).

## License

Coroot-node-agent is licensed under the [Apache License, Version 2.0](https://github.com/coroot/coroot-node-agent/blob/main/LICENSE).

The BPF code is licensed under the General Public License, Version 2.0.
