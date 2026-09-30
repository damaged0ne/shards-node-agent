package containers

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

// Shards fork: Docker Compose grouping and Docker-level container metrics.

const (
	shardsIgnoreLabel  = "shards.ignore"
	releaseWindowLabel = "shards.release-window"

	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
	composeNumberLabel  = "com.docker.compose.container-number"
	composeOneoffLabel  = "com.docker.compose.oneoff"

	dockerListTTL    = 5 * time.Second
	dockerInspectTTL = time.Minute
)

// shardsIgnored reports whether the container is excluded with the shards.ignore=true label.
func shardsIgnored(md *ContainerMetadata) bool {
	return md.labels[shardsIgnoreLabel] == "true"
}

// composeContainerId maps a Docker Compose container to the Swarm-shaped id /swarm/<project>/<service>/<instance>,
// which Coroot turns into a single application per service with the project as its namespace.
// One-off containers (`docker compose run`) are grouped into the <service>-run application.
func composeContainerId(md *ContainerMetadata) ContainerID {
	if !*flags.ComposeGrouping {
		return ""
	}
	project, service := md.labels[composeProjectLabel], md.labels[composeServiceLabel]
	if project == "" || service == "" || strings.Contains(project+service, "/") {
		return ""
	}
	if strings.EqualFold(md.labels[composeOneoffLabel], "true") {
		// v2: <project>-<service>-run-<hex>, v1: <project>_<service>_run_<n>
		instance := md.name
		if i := strings.LastIndexAny(instance, "-_"); i >= 0 {
			instance = instance[i+1:]
		}
		if instance == "" {
			return ""
		}
		return ContainerID(fmt.Sprintf("/swarm/%s/%s-run/%s", project, service, instance))
	}
	number := md.labels[composeNumberLabel]
	if number == "" {
		number = "1"
	}
	return ContainerID(fmt.Sprintf("/swarm/%s/%s/%s", project, service, number))
}

// dockerCollector exports metrics that come from the Docker API rather than from cgroups,
// so it also covers containers that aren't running.
type dockerCollector struct {
	lock       sync.Mutex
	listedAt   time.Time
	containers []dockerContainer
	inspected  map[string]*dockerInspect

	labelKeys []string
	labelDesc *prometheus.Desc

	now func() time.Time
}

type dockerContainer struct {
	id      ContainerID
	summary container.Summary
	inspect *dockerInspect
}

type dockerInspect struct {
	at         time.Time
	state      container.ContainerState
	exitCode   int
	oomKilled  bool
	startedAt  time.Time
	finishedAt time.Time
	restarts   int
	policy     string
}

var invalidLabelChars = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func newDockerCollector(labels []string) *dockerCollector {
	c := &dockerCollector{inspected: map[string]*dockerInspect{}, now: time.Now}
	seen := map[string]bool{}
	var names []string
	for _, l := range labels {
		name := "label_" + strings.ToLower(invalidLabelChars.ReplaceAllString(l, "_"))
		if l == "" || seen[name] {
			continue
		}
		seen[name] = true
		c.labelKeys = append(c.labelKeys, l)
		names = append(names, name)
	}
	if len(names) > 0 {
		c.labelDesc = prometheus.NewDesc("shards_container_labels", "Docker labels of the container selected with --container-labels", append([]string{"container_id"}, names...), nil)
	}
	return c
}

func (c *dockerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.ShardsContainerHealth
	ch <- metrics.ShardsComposeInfo
	ch <- metrics.ShardsContainerState
	ch <- metrics.ShardsContainerExitCode
	ch <- metrics.ShardsContainerOOMKilled
	ch <- metrics.ShardsContainerStarted
	ch <- metrics.ShardsContainerFinished
	ch <- metrics.ShardsContainerDockerRestart
	ch <- metrics.ShardsContainerRestartPolicy
	ch <- metrics.ShardsContainerImageInfo
	if c.labelDesc != nil {
		ch <- c.labelDesc
	}
}

func (c *dockerCollector) Collect(ch chan<- prometheus.Metric) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if time.Since(c.listedAt) > dockerListTTL {
		c.listedAt = time.Now()
		if err := c.refresh(); err != nil {
			klog.Warningln("failed to list docker containers:", err)
		}
	}
	for _, dc := range c.containers {
		c.emit(ch, dc)
	}
}

func (c *dockerCollector) refresh() error {
	if dockerdClient == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerdTimeout)
	defer cancel()
	res, err := dockerdClient.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return err
	}
	c.containers = c.containers[:0]
	seen := map[string]bool{}
	for _, s := range res.Items {
		id := dockerSummaryId(s)
		if id == "" || common.ContainerFilter.ShouldBeSkipped(string(id)) {
			continue
		}
		seen[s.ID] = true
		dc := dockerContainer{id: id, summary: s, inspect: c.inspected[s.ID]}
		if dc.inspect == nil || dc.inspect.state != s.State || time.Since(dc.inspect.at) > dockerInspectTTL {
			if i, err := dockerInspectContainer(ctx, s.ID); err != nil {
				klog.Warningln("failed to inspect docker container:", err)
			} else {
				dc.inspect = i
				c.inspected[s.ID] = i
			}
		}
		c.containers = append(c.containers, dc)
	}
	for id := range c.inspected {
		if !seen[id] {
			delete(c.inspected, id)
		}
	}
	c.containers = dedupDockerContainers(c.containers)
	return nil
}

// dockerSummaryId computes the same id the registry assigns to the container's cgroup.
func dockerSummaryId(s container.Summary) ContainerID {
	name := ""
	if len(s.Names) > 0 {
		name = strings.TrimPrefix(s.Names[0], "/")
	}
	md := &ContainerMetadata{name: name, labels: s.Labels}
	if shardsIgnored(md) {
		return ""
	}
	return calcId(&cgroup.Cgroup{ContainerType: cgroup.ContainerTypeDocker, ContainerId: s.ID}, md)
}

// dedupDockerContainers keeps one container per id (e.g. a leftover exited replica next to its running
// successor): running containers win, then the most recently created one. Duplicate series would fail the scrape.
func dedupDockerContainers(containers []dockerContainer) []dockerContainer {
	byId := map[ContainerID]int{}
	var res []dockerContainer
	for _, dc := range containers {
		i, ok := byId[dc.id]
		if !ok {
			byId[dc.id] = len(res)
			res = append(res, dc)
			continue
		}
		cur := res[i].summary
		running, curRunning := dc.summary.State == container.StateRunning, cur.State == container.StateRunning
		if running && !curRunning || running == curRunning && dc.summary.Created > cur.Created {
			res[i] = dc
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].id < res[j].id })
	return res
}

func dockerInspectContainer(ctx context.Context, containerId string) (*dockerInspect, error) {
	res, err := dockerdClient.ContainerInspect(ctx, containerId, client.ContainerInspectOptions{})
	if err != nil {
		return nil, err
	}
	c := res.Container
	i := &dockerInspect{at: time.Now(), restarts: c.RestartCount}
	if c.State != nil {
		i.state = container.ContainerState(c.State.Status)
		i.exitCode = c.State.ExitCode
		i.oomKilled = c.State.OOMKilled
		i.startedAt = parseDockerTime(c.State.StartedAt)
		i.finishedAt = parseDockerTime(c.State.FinishedAt)
	}
	if c.HostConfig != nil {
		i.policy = string(c.HostConfig.RestartPolicy.Name)
	}
	return i, nil
}

// parseDockerTime returns the zero time for unset values, which dockerd reports as 0001-01-01T00:00:00Z.
func parseDockerTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 2000 {
		return time.Time{}
	}
	return t
}

func (c *dockerCollector) emit(ch chan<- prometheus.Metric, dc dockerContainer) {
	id := string(dc.id)
	s := dc.summary
	labels := s.Labels // includes the labels of the image

	ch <- metrics.Gauge(metrics.ShardsContainerState, 1, id, string(s.State))
	if h := dockerHealthStatus(s); h != "" && s.State == container.StateRunning {
		ch <- metrics.Gauge(metrics.ShardsContainerHealth, 1, id, string(h))
	}
	if project, service := labels[composeProjectLabel], labels[composeServiceLabel]; project != "" || service != "" {
		ch <- metrics.Gauge(metrics.ShardsComposeInfo, 1, id, project, service)
	}
	ch <- metrics.Gauge(metrics.ShardsContainerImageInfo, 1, id, s.Image, s.ImageID,
		labels["org.opencontainers.image.version"], labels["org.opencontainers.image.revision"])
	if s.Created > 0 {
		created := time.Unix(s.Created, 0)
		ch <- metrics.Gauge(metrics.ShardsContainerCreated, float64(s.Created), id)
		// one-off `compose run` containers are jobs, not releases
		if !strings.EqualFold(labels[composeOneoffLabel], "true") {
			if w := releaseWindow(labels); w > 0 {
				if left := created.Add(w).Sub(c.now()); left > 0 {
					ch <- metrics.Gauge(metrics.ShardsReleaseWindow, left.Seconds(), id, releaseVersion(s), s.ImageID)
				}
			}
		}
	}
	if c.labelDesc != nil {
		values := []string{id}
		for _, k := range c.labelKeys {
			values = append(values, labels[k])
		}
		ch <- metrics.Gauge(c.labelDesc, 1, values...)
	}

	i := dc.inspect
	if i == nil {
		return
	}
	if !i.startedAt.IsZero() {
		ch <- metrics.Gauge(metrics.ShardsContainerStarted, float64(i.startedAt.Unix()), id)
	}
	if s.State != container.StateRunning && s.State != container.StatePaused {
		if !i.finishedAt.IsZero() {
			ch <- metrics.Gauge(metrics.ShardsContainerFinished, float64(i.finishedAt.Unix()), id)
		}
		if s.State != container.StateCreated {
			ch <- metrics.Gauge(metrics.ShardsContainerExitCode, float64(i.exitCode), id)
			oom := 0.
			if i.oomKilled {
				oom = 1
			}
			ch <- metrics.Gauge(metrics.ShardsContainerOOMKilled, oom, id)
		}
	}
	ch <- metrics.Gauge(metrics.ShardsContainerDockerRestart, float64(i.restarts), id)
	if i.policy != "" {
		ch <- metrics.Gauge(metrics.ShardsContainerRestartPolicy, 1, id, i.policy)
	}
}

func dockerHealthStatus(c container.Summary) container.HealthStatus {
	if c.Health != nil && c.Health.Status != container.NoHealthcheck {
		return c.Health.Status
	}
	// older daemons don't return the Health field, the status is only present in the text: "Up 5 minutes (healthy)"
	switch {
	case strings.HasSuffix(c.Status, "(healthy)"):
		return container.Healthy
	case strings.HasSuffix(c.Status, "(unhealthy)"):
		return container.Unhealthy
	case strings.HasSuffix(c.Status, "(health: starting)"):
		return container.Starting
	}
	return ""
}

// releaseWindow returns the window set with the shards.release-window label (e.g. "45m", "0" disables),
// falling back to --release-window.
func releaseWindow(labels map[string]string) time.Duration {
	if v := labels[releaseWindowLabel]; v != "" {
		if v == "0" {
			return 0
		}
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			return d
		}
	}
	return *flags.ReleaseWindow
}

// releaseVersion prefers the OCI version label, then the image tag, then the short image id.
func releaseVersion(s container.Summary) string {
	if v := s.Labels["org.opencontainers.image.version"]; v != "" {
		return v
	}
	image := s.Image
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i >= 0 && !strings.Contains(image[i:], "/") {
		return image[i+1:]
	}
	id := strings.TrimPrefix(s.ImageID, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}
