package containers

import (
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/assert"
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
