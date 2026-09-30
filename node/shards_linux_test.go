package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostMounts(t *testing.T) {
	mounts, err := hostMounts("fixtures/proc")
	require.NoError(t, err)
	assert.Equal(t, []Mount{
		{MajorMinor: "259:2", MountPoint: "/", FsType: "ext4", Device: "/dev/nvme0n1p2"},
		{MajorMinor: "259:1", MountPoint: "/boot/efi", FsType: "vfat", Device: "/dev/nvme0n1p1"},
		{MajorMinor: "8:16", MountPoint: "/mnt/my data", FsType: "xfs", Device: "/dev/sdb", ReadOnly: true},
		{MajorMinor: "0:50", MountPoint: "/tank", FsType: "zfs", Device: "tank"},
	}, mounts)
}

func TestLoadAvg(t *testing.T) {
	la, err := loadAvg("fixtures/proc")
	require.NoError(t, err)
	assert.Equal(t, [3]float64{0.52, 0.58, 0.59}, la)
}
