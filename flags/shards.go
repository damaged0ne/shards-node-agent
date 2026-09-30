package flags

import "gopkg.in/alecthomas/kingpin.v2"

// Shards fork flags.
var (
	HostnameOverride = kingpin.Flag("hostname-override", "Report this hostname instead of the one from the host's UTS namespace").Envar(envar("HOSTNAME_OVERRIDE")).String()
)

var (
	DisableNftablesMonitoring = kingpin.Flag("disable-nftables-monitoring", "Disable collecting nftables counters").Default("false").Envar(envar("DISABLE_NFTABLES_MONITORING")).Bool()
	DisableFail2banMonitoring = kingpin.Flag("disable-fail2ban-monitoring", "Disable collecting fail2ban bans").Default("false").Envar(envar("DISABLE_FAIL2BAN_MONITORING")).Bool()
	Fail2banDB                = kingpin.Flag("fail2ban-db", "Path to the fail2ban database on the host").Default("/var/lib/fail2ban/fail2ban.sqlite3").Envar(envar("FAIL2BAN_DB")).String()
)

var (
	ComposeGrouping = kingpin.Flag("compose-grouping", "Report Docker Compose containers as /swarm/<project>/<service>/<number> so that Coroot groups replicas into one application per service (--no-compose-grouping reports them as /docker/<name>)").Default("true").Envar(envar("COMPOSE_GROUPING")).Bool()
	ContainerLabels = kingpin.Flag("container-labels", "Docker labels to export as labels of the shards_container_labels metric").Envar(envar("CONTAINER_LABELS")).Strings()
)
