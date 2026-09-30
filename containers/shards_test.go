package containers

import (
	"strings"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/moby/moby/api/types/container"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerHealthStatus(t *testing.T) {
	for _, tc := range []struct {
		summary  container.Summary
		expected container.HealthStatus
	}{
		{container.Summary{Health: &container.HealthSummary{Status: container.Unhealthy}}, container.Unhealthy},
		{container.Summary{Health: &container.HealthSummary{Status: container.NoHealthcheck}, Status: "Up 2 hours"}, ""},
		{container.Summary{Status: "Up 5 minutes (healthy)"}, container.Healthy},
		{container.Summary{Status: "Up 5 minutes (unhealthy)"}, container.Unhealthy},
		{container.Summary{Status: "Up 3 seconds (health: starting)"}, container.Starting},
		{container.Summary{Status: "Up 2 hours"}, ""},
	} {
		assert.Equal(t, tc.expected, dockerHealthStatus(tc.summary), tc.summary.Status)
	}
}

func withComposeGrouping(t *testing.T, enabled bool) {
	prev := *flags.ComposeGrouping
	*flags.ComposeGrouping = enabled
	t.Cleanup(func() { *flags.ComposeGrouping = prev })
}

func composeLabels(project, service, number string) map[string]string {
	return map[string]string{
		"com.docker.compose.project":          project,
		"com.docker.compose.service":          service,
		"com.docker.compose.container-number": number,
	}
}

func TestCalcIdCompose(t *testing.T) {
	withComposeGrouping(t, true)
	docker := &cgroup.Cgroup{ContainerType: cgroup.ContainerTypeDocker, ContainerId: "abc"}
	id := func(name string, labels map[string]string) ContainerID {
		return calcId(docker, &ContainerMetadata{name: name, labels: labels})
	}

	assert.Equal(t, ContainerID("/swarm/mimir/api/2"), id("mimir-api-2", composeLabels("mimir", "api", "2")))
	assert.Equal(t, ContainerID("/swarm/mimir/api/1"), id("mimir-api-1", composeLabels("mimir", "api", "")))
	assert.Equal(t, ContainerID("/docker/plain"), id("plain", nil))

	oneoff := composeLabels("mimir", "migrate", "1")
	oneoff["com.docker.compose.oneoff"] = "True"
	assert.Equal(t, ContainerID("/swarm/mimir/migrate-run/3f2a9c1b"), id("mimir-migrate-run-3f2a9c1b", oneoff))
	assert.Equal(t, ContainerID("/swarm/mimir/migrate-run/4"), id("mimir_migrate_run_4", oneoff))

	ignored := composeLabels("mimir", "api", "1")
	ignored["shards.ignore"] = "true"
	assert.Equal(t, ContainerID(""), id("mimir-api-1", ignored))

	// real swarm tasks keep their own ids
	swarm := composeLabels("mimir", "api", "1")
	swarm["com.docker.swarm.task.name"] = "stack_web.3.xyz"
	swarm["com.docker.swarm.service.name"] = "stack_web"
	swarm["com.docker.stack.namespace"] = "stack"
	assert.Equal(t, ContainerID("/swarm/stack/web/3"), id("stack_web.3.xyz", swarm))

	withComposeGrouping(t, false)
	assert.Equal(t, ContainerID("/docker/mimir-api-2"), id("mimir-api-2", composeLabels("mimir", "api", "2")))
}

func TestDedupDockerContainers(t *testing.T) {
	cs := dedupDockerContainers([]dockerContainer{
		{id: "/swarm/p/api/1", summary: container.Summary{ID: "old", State: container.StateExited, Created: 100}},
		{id: "/swarm/p/api/1", summary: container.Summary{ID: "new", State: container.StateRunning, Created: 50}},
		{id: "/swarm/p/job/1", summary: container.Summary{ID: "a", State: container.StateExited, Created: 100}},
		{id: "/swarm/p/job/1", summary: container.Summary{ID: "b", State: container.StateExited, Created: 200}},
	})
	require.Len(t, cs, 2)
	assert.Equal(t, "new", cs[0].summary.ID)
	assert.Equal(t, "b", cs[1].summary.ID)
}

func TestParseDockerTime(t *testing.T) {
	assert.True(t, parseDockerTime("0001-01-01T00:00:00Z").IsZero())
	assert.True(t, parseDockerTime("").IsZero())
	assert.Equal(t, int64(1790000000), parseDockerTime("2026-09-21T14:13:20.123456789Z").Unix())
}

func TestDockerCollectorEmit(t *testing.T) {
	c := newDockerCollector([]string{"team", "org.opencontainers.image.version", "team", ""})
	c.listedAt = time.Now() // don't call dockerd
	labels := composeLabels("mimir", "api", "1")
	labels["team"] = "core"
	labels["org.opencontainers.image.version"] = "1.4.2"
	labels["org.opencontainers.image.revision"] = "abc123"
	started := time.Unix(1_790_000_000, 0)
	c.containers = []dockerContainer{
		{
			id:      "/swarm/mimir/api/1",
			summary: container.Summary{State: container.StateRunning, Status: "Up 1 hour (unhealthy)", Image: "mimir:1.4.2", ImageID: "sha256:1", Labels: labels},
			inspect: &dockerInspect{state: container.StateRunning, startedAt: started, restarts: 2, policy: "always"},
		},
		{
			id:      "/docker/cron",
			summary: container.Summary{State: container.StateExited, Status: "Exited (137) 5 minutes ago", Image: "cron", ImageID: "sha256:2"},
			inspect: &dockerInspect{state: container.StateExited, exitCode: 137, oomKilled: true, startedAt: started, finishedAt: started.Add(time.Minute), policy: "no"},
		},
	}
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)
	got := map[string]float64{}
	for m := range ch {
		var d dto.Metric
		require.NoError(t, m.Write(&d))
		desc := m.Desc().String()
		key := desc[len(`Desc{fqName: "`):strings.Index(desc, `", help`)]
		for _, l := range d.Label {
			key += " " + l.GetName() + "=" + l.GetValue()
		}
		got[key] = d.GetGauge().GetValue()
	}
	assert.Equal(t, map[string]float64{
		"shards_container_state container_id=/swarm/mimir/api/1 state=running":                                                          1,
		"shards_container_health container_id=/swarm/mimir/api/1 status=unhealthy":                                                      1,
		"shards_compose_info container_id=/swarm/mimir/api/1 project=mimir service=api":                                                 1,
		"shards_container_image_info container_id=/swarm/mimir/api/1 image=mimir:1.4.2 image_id=sha256:1 revision=abc123 version=1.4.2": 1,
		"shards_container_labels container_id=/swarm/mimir/api/1 label_org_opencontainers_image_version=1.4.2 label_team=core":          1,
		"shards_container_started_seconds container_id=/swarm/mimir/api/1":                                                              1_790_000_000,
		"shards_container_docker_restarts container_id=/swarm/mimir/api/1":                                                              2,
		"shards_container_restart_policy container_id=/swarm/mimir/api/1 policy=always":                                                 1,
		"shards_container_state container_id=/docker/cron state=exited":                                                                 1,
		"shards_container_image_info container_id=/docker/cron image=cron image_id=sha256:2 revision= version=":                         1,
		"shards_container_labels container_id=/docker/cron label_org_opencontainers_image_version= label_team=":                         1,
		"shards_container_started_seconds container_id=/docker/cron":                                                                    1_790_000_000,
		"shards_container_finished_seconds container_id=/docker/cron":                                                                   1_790_000_060,
		"shards_container_exit_code container_id=/docker/cron":                                                                          137,
		"shards_container_oom_killed container_id=/docker/cron":                                                                         1,
		"shards_container_docker_restarts container_id=/docker/cron":                                                                    0,
		"shards_container_restart_policy container_id=/docker/cron policy=no":                                                           1,
	}, got)
}

func TestReleaseVersion(t *testing.T) {
	for _, tc := range []struct {
		summary  container.Summary
		expected string
	}{
		{container.Summary{Image: "mimir:1.4.2", Labels: map[string]string{"org.opencontainers.image.version": "1.5.0"}}, "1.5.0"},
		{container.Summary{Image: "registry.local:5000/mimir:1.4.2"}, "1.4.2"},
		{container.Summary{Image: "mimir:1.4.2@sha256:ffff"}, "1.4.2"},
		{container.Summary{Image: "registry.local:5000/mimir", ImageID: "sha256:0123456789abcdef"}, "0123456789ab"},
	} {
		assert.Equal(t, tc.expected, releaseVersion(tc.summary), tc.summary.Image)
	}
}

func TestReleaseWindow(t *testing.T) {
	prev := *flags.ReleaseWindow
	*flags.ReleaseWindow = 30 * time.Minute
	t.Cleanup(func() { *flags.ReleaseWindow = prev })

	now := time.Unix(1_790_000_000, 0)
	c := newDockerCollector(nil)
	c.listedAt = now
	c.now = func() time.Time { return now }
	created := func(ago time.Duration) int64 { return now.Add(-ago).Unix() }
	oneoff := map[string]string{"com.docker.compose.oneoff": "True"}
	c.containers = []dockerContainer{
		{id: "/swarm/p/fresh/1", summary: container.Summary{Created: created(10 * time.Minute), Image: "fresh:2", ImageID: "sha256:a"}},
		{id: "/swarm/p/old/1", summary: container.Summary{Created: created(time.Hour), Image: "old:1"}},
		{id: "/swarm/p/slow/1", summary: container.Summary{Created: created(time.Hour), Image: "slow:3", ImageID: "sha256:b",
			Labels: map[string]string{"shards.release-window": "2h"}}},
		{id: "/swarm/p/quiet/1", summary: container.Summary{Created: created(time.Minute), Image: "quiet:1",
			Labels: map[string]string{"shards.release-window": "0"}}},
		{id: "/swarm/p/job-run/abc", summary: container.Summary{Created: created(time.Minute), Image: "job:1", Labels: oneoff}},
	}
	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)
	windows := map[string]float64{}
	created_ := 0
	for m := range ch {
		desc := m.Desc().String()
		var d dto.Metric
		require.NoError(t, m.Write(&d))
		switch {
		case strings.Contains(desc, `"shards_release_window"`):
			key := ""
			for _, l := range d.Label {
				key += l.GetName() + "=" + l.GetValue() + " "
			}
			windows[strings.TrimSpace(key)] = d.GetGauge().GetValue()
		case strings.Contains(desc, `"shards_container_created_seconds"`):
			created_++
		}
	}
	assert.Equal(t, 5, created_)
	assert.Equal(t, map[string]float64{
		"container_id=/swarm/p/fresh/1 image_id=sha256:a version=2": (20 * time.Minute).Seconds(),
		"container_id=/swarm/p/slow/1 image_id=sha256:b version=3":  time.Hour.Seconds(),
	}, windows)
}
