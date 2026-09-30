package node

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	NodePsiCPU    = prometheus.NewDesc("node_resources_cpu_pressure_waiting_seconds_total", "Total time in seconds that processes on the node were delayed due to CPU pressure", []string{"kind"}, nil)
	NodePsiMemory = prometheus.NewDesc("node_resources_memory_pressure_waiting_seconds_total", "Total time in seconds that processes on the node were delayed due to memory pressure", []string{"kind"}, nil)
	NodePsiIO     = prometheus.NewDesc("node_resources_io_pressure_waiting_seconds_total", "Total time in seconds that processes on the node were delayed due to I/O pressure", []string{"kind"}, nil)
)

// pressure reads <procRoot>/pressure/<resource> (PSI, Linux 4.20+) and returns the total stall
// time in seconds by kind ("some", "full"). Only the kinds present in the file are returned.
func pressure(procRoot, resource string) (map[string]float64, error) {
	data, err := os.ReadFile(path.Join(procRoot, "pressure", resource))
	if err != nil {
		return nil, err
	}
	res := map[string]float64{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		kind := parts[0]
		if kind != "some" && kind != "full" {
			continue
		}
		for _, p := range parts[1:] {
			if v, ok := strings.CutPrefix(p, "total="); ok {
				us, err := strconv.ParseUint(v, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid pressure/%s: %w", resource, err)
				}
				res[kind] = float64(us) / 1e6 // microseconds to seconds
				break
			}
		}
	}
	return res, nil
}
