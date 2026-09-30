package containers

import (
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/proc"
	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

func TestGcClosedConnections(t *testing.T) {
	now := time.Now()
	open := &ActiveConnection{Pid: 1, Fd: 10}
	recentlyClosed := &ActiveConnection{Pid: 1, Fd: 11, Closed: now.Add(-closedConnectionsTTL / 2)}
	closed := &ActiveConnection{Pid: 1, Fd: 12, Closed: now.Add(-2 * closedConnectionsTTL)}
	reused := &ActiveConnection{Pid: 1, Fd: 13}
	closedWithReusedFd := &ActiveConnection{Pid: 1, Fd: 13, Closed: now.Add(-2 * closedConnectionsTTL)}

	key := func(port uint16) ConnectionKey {
		return ConnectionKey{
			src: netaddr.IPPortFrom(netaddr.MustParseIP("10.0.0.1"), port),
			dst: netaddr.IPPortFrom(netaddr.MustParseIP("10.0.0.2"), 80),
		}
	}
	c := &Container{
		activeConnections: map[ConnectionKey]*ActiveConnection{
			key(1): open, key(2): recentlyClosed, key(3): closed, key(4): reused, key(5): closedWithReusedFd,
		},
		connectionsByPidFd: map[PidFd]*ActiveConnection{
			{Pid: 1, Fd: 10}: open, {Pid: 1, Fd: 11}: recentlyClosed, {Pid: 1, Fd: 12}: closed, {Pid: 1, Fd: 13}: reused,
		},
	}
	c.gcClosedConnections(now)

	assert.Equal(t, map[ConnectionKey]*ActiveConnection{key(1): open, key(2): recentlyClosed, key(4): reused}, c.activeConnections)
	assert.Equal(t, map[PidFd]*ActiveConnection{{Pid: 1, Fd: 10}: open, {Pid: 1, Fd: 11}: recentlyClosed, {Pid: 1, Fd: 13}: reused}, c.connectionsByPidFd)
}

func TestLogMonitoringDisabled(t *testing.T) {
	c := &Container{metadata: &ContainerMetadata{}, processes: map[uint32]*Process{}}
	assert.False(t, c.logMonitoringDisabled())

	// the flag from the container's runtime metadata is known before any process is registered
	c.metadata.env = map[string]string{"COROOT_LOG_MONITORING": "disabled"}
	assert.True(t, c.logMonitoringDisabled())

	c.metadata.env = nil
	c.processes[1] = &Process{Pid: 1}
	assert.False(t, c.logMonitoringDisabled())
	c.processes[2] = &Process{Pid: 2, Flags: proc.Flags{LogMonitoringDisabled: true}}
	assert.True(t, c.logMonitoringDisabled())
}
