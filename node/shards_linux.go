package node

import (
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const statfsTimeout = 5 * time.Second

var (
	ignoredFsTypes = map[string]bool{
		"autofs": true, "binfmt_misc": true, "bpf": true, "cgroup": true, "cgroup2": true, "configfs": true,
		"debugfs": true, "devpts": true, "devtmpfs": true, "efivarfs": true, "fuse.lxcfs": true, "fusectl": true,
		"hugetlbfs": true, "mqueue": true, "nsfs": true, "overlay": true, "proc": true, "pstore": true,
		"ramfs": true, "rpc_pipefs": true, "securityfs": true, "selinuxfs": true, "squashfs": true,
		"sysfs": true, "tmpfs": true, "tracefs": true, "nfsd": true, "erofs": true,
	}
	ignoredMountPoints = regexp.MustCompile(`^/(dev|proc|sys|run|snap|var/lib/docker/.+|var/lib/containerd/.+|var/lib/containers/storage/.+|var/lib/kubelet/.+)($|/)`)

	pendingStatfs    = map[string]bool{}
	pendingStatfsMu  sync.Mutex
	errStatfsPending = errors.New("statfs pending")
)

type Mount struct {
	MajorMinor string
	MountPoint string
	FsType     string
	Device     string
	ReadOnly   bool
}

// hostMounts returns real filesystems from the host mount namespace, one per device.
func hostMounts(procRoot string) ([]Mount, error) {
	data, err := os.ReadFile(path.Join(procRoot, "1/mountinfo"))
	if err != nil {
		return nil, err
	}
	var res []Mount
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		sep := slices.Index(fields[6:], "-")
		if sep == -1 || 6+sep+2 >= len(fields) {
			continue
		}
		m := Mount{
			MajorMinor: fields[2],
			MountPoint: unescapeMountPath(fields[4]),
			FsType:     fields[6+sep+1],
			Device:     fields[6+sep+2],
			ReadOnly:   slices.Contains(strings.Split(fields[5], ","), "ro"),
		}
		if ignoredFsTypes[m.FsType] || ignoredMountPoints.MatchString(m.MountPoint) {
			continue
		}
		if seen[m.MajorMinor] {
			continue
		}
		seen[m.MajorMinor] = true
		res = append(res, m)
	}
	return res, nil
}

// mountinfo escapes space, tab, newline and backslash as octal sequences.
func unescapeMountPath(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// statfsWithTimeout doesn't let a hung mount (e.g. a dead network share) block the collection.
// Such a mount point is skipped until its pending statfs call returns.
func statfsWithTimeout(mountPoint string) (*unix.Statfs_t, error) {
	pendingStatfsMu.Lock()
	if pendingStatfs[mountPoint] {
		pendingStatfsMu.Unlock()
		return nil, errStatfsPending
	}
	pendingStatfs[mountPoint] = true
	pendingStatfsMu.Unlock()

	type result struct {
		st  unix.Statfs_t
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var r result
		r.err = unix.Statfs(proc.HostPath(mountPoint), &r.st)
		pendingStatfsMu.Lock()
		delete(pendingStatfs, mountPoint)
		pendingStatfsMu.Unlock()
		ch <- r
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return &r.st, nil
	case <-time.After(statfsTimeout):
		return nil, fmt.Errorf("statfs on %s timed out", mountPoint)
	}
}

func collectFilesystems(ch chan<- prometheus.Metric) {
	mounts, err := hostMounts(procRoot)
	if err != nil {
		klog.Errorln("failed to read host mounts:", err)
		return
	}
	for _, m := range mounts {
		st, err := statfsWithTimeout(m.MountPoint)
		if err != nil {
			if !errors.Is(err, errStatfsPending) {
				klog.Warningln(err)
			}
			continue
		}
		bsize := float64(st.Bsize)
		ch <- metrics.Gauge(metrics.ShardsFsSize, float64(st.Blocks)*bsize, m.MountPoint, m.Device, m.FsType)
		ch <- metrics.Gauge(metrics.ShardsFsAvail, float64(st.Bavail)*bsize, m.MountPoint, m.Device, m.FsType)
		ch <- metrics.Gauge(metrics.ShardsFsFiles, float64(st.Files), m.MountPoint, m.Device, m.FsType)
		ch <- metrics.Gauge(metrics.ShardsFsFilesFree, float64(st.Ffree), m.MountPoint, m.Device, m.FsType)
		ro := 0.
		if m.ReadOnly {
			ro = 1
		}
		ch <- metrics.Gauge(metrics.ShardsFsReadonly, ro, m.MountPoint, m.Device, m.FsType)
	}
}

func loadAvg(procRoot string) ([3]float64, error) {
	var res [3]float64
	data, err := os.ReadFile(path.Join(procRoot, "loadavg"))
	if err != nil {
		return res, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return res, fmt.Errorf("invalid format of /proc/loadavg")
	}
	for i := 0; i < 3; i++ {
		if res[i], err = strconv.ParseFloat(fields[i], 64); err != nil {
			return res, err
		}
	}
	return res, nil
}

func collectShards(ch chan<- prometheus.Metric) {
	if la, err := loadAvg(procRoot); err != nil {
		klog.Errorln(err)
	} else {
		ch <- metrics.Gauge(metrics.ShardsLoad1, la[0])
		ch <- metrics.Gauge(metrics.ShardsLoad5, la[1])
		ch <- metrics.Gauge(metrics.ShardsLoad15, la[2])
	}
	collectFilesystems(ch)
}
