package flags

import "gopkg.in/alecthomas/kingpin.v2"

// Shards fork flags.
var (
	HostnameOverride = kingpin.Flag("hostname-override", "Report this hostname instead of the one from the host's UTS namespace").Envar(envar("HOSTNAME_OVERRIDE")).String()
)
