package proc

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strconv"
	"sync"
	"time"
)

// userHZ is the kernel's USER_HZ, the unit of the starttime field of /proc/<pid>/stat.
// It is 100 on all architectures supported by Linux userspace ABIs.
const userHZ = 100

var (
	bootTime     time.Time
	bootTimeErr  error
	bootTimeOnce sync.Once
)

func getBootTime() (time.Time, error) {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile(path.Join(root, "stat"))
		if err != nil {
			bootTimeErr = err
			return
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			if v, ok := bytes.CutPrefix(line, []byte("btime ")); ok {
				sec, err := strconv.ParseInt(string(bytes.TrimSpace(v)), 10, 64)
				if err != nil {
					bootTimeErr = err
					return
				}
				bootTime = time.Unix(sec, 0)
				return
			}
		}
		bootTimeErr = fmt.Errorf("btime not found in %s/stat", root)
	})
	return bootTime, bootTimeErr
}

// GetStartTime returns the start time of the process, read from procfs.
// Unlike taskstats (netlink), it doesn't depend on delay accounting support in the kernel.
func GetStartTime(pid uint32) (time.Time, error) {
	bt, err := getBootTime()
	if err != nil {
		return time.Time{}, err
	}
	data, err := os.ReadFile(Path(pid, "stat"))
	if err != nil {
		return time.Time{}, err
	}
	// the process name (field 2) may contain spaces and parentheses, so start parsing after the last ')'
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return time.Time{}, fmt.Errorf("invalid stat file of pid %d", pid)
	}
	fields := bytes.Fields(data[i+1:])
	// fields[0] is field 3 (state), so starttime (field 22) is fields[19]
	if len(fields) < 20 {
		return time.Time{}, fmt.Errorf("invalid stat file of pid %d", pid)
	}
	ticks, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return bt.Add(time.Duration(ticks) * time.Second / userHZ), nil
}
