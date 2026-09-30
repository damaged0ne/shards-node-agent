package containers

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/cgroup"
	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

// Shards fork: Docker healthcheck status and Compose labels.

const dockerHealthTTL = 5 * time.Second

var dockerHealth = &dockerHealthCache{}

// dockerHealthCache refreshes health statuses of all running containers with a single list call,
// so that per-container collection doesn't hit dockerd.
type dockerHealthCache struct {
	lock      sync.Mutex
	updatedAt time.Time
	byId      map[string]container.HealthStatus
}

func (c *dockerHealthCache) get(containerId string) container.HealthStatus {
	c.lock.Lock()
	defer c.lock.Unlock()
	if time.Since(c.updatedAt) > dockerHealthTTL {
		c.updatedAt = time.Now()
		byId, err := listDockerHealth()
		if err != nil {
			klog.Warningln("failed to list docker containers:", err)
		}
		c.byId = byId
	}
	return c.byId[containerId]
}

func listDockerHealth() (map[string]container.HealthStatus, error) {
	if dockerdClient == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerdTimeout)
	defer cancel()
	res, err := dockerdClient.ContainerList(ctx, client.ContainerListOptions{})
	if err != nil {
		return nil, err
	}
	byId := make(map[string]container.HealthStatus, len(res.Items))
	for _, c := range res.Items {
		if s := dockerHealthStatus(c); s != "" {
			byId[c.ID] = s
		}
	}
	return byId, nil
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

func (c *Container) collectShards(ch chan<- prometheus.Metric) {
	if project, service := c.metadata.labels["com.docker.compose.project"], c.metadata.labels["com.docker.compose.service"]; project != "" || service != "" {
		ch <- metrics.Gauge(metrics.ShardsComposeInfo, 1, project, service)
	}
	if c.cgroup.ContainerType == cgroup.ContainerTypeDocker && c.cgroup.ContainerId != "" {
		if s := dockerHealth.get(c.cgroup.ContainerId); s != "" {
			ch <- metrics.Gauge(metrics.ShardsContainerHealth, 1, string(s))
		}
	}
}
