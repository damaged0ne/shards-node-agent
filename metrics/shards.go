package metrics

// Shards fork metrics. Kept separate from metrics.go to simplify upstream merges.
var (
	ShardsFsSize      = metric("shards_fs_size_bytes", "Filesystem size in bytes", "mount", "device", "fs")
	ShardsFsAvail     = metric("shards_fs_avail_bytes", "Filesystem space available to non-root users in bytes", "mount", "device", "fs")
	ShardsFsFiles     = metric("shards_fs_files", "Filesystem total inodes", "mount", "device", "fs")
	ShardsFsFilesFree = metric("shards_fs_files_free", "Filesystem free inodes", "mount", "device", "fs")
	ShardsFsReadonly  = metric("shards_fs_readonly", "1 if the filesystem is mounted read-only", "mount", "device", "fs")

	ShardsLoad1  = metric("shards_load1", "1m load average")
	ShardsLoad5  = metric("shards_load5", "5m load average")
	ShardsLoad15 = metric("shards_load15", "15m load average")

	ShardsContainerHealth = metric("shards_container_health", "Docker healthcheck status of the container (series present with value 1 for the current status)", "status")
	ShardsComposeInfo     = metric("shards_compose_info", "Docker Compose project and service of the container", "project", "service")

	ShardsNftCounterBytes   = metric("shards_nft_counter_bytes_total", "Bytes matched by a named nftables counter", "family", "table", "counter")
	ShardsNftCounterPackets = metric("shards_nft_counter_packets_total", "Packets matched by a named nftables counter", "family", "table", "counter")
	ShardsNftRuleBytes      = metric("shards_nft_rule_bytes_total", "Bytes matched by nftables rules with a counter and a comment", "family", "table", "chain", "comment")
	ShardsNftRulePackets    = metric("shards_nft_rule_packets_total", "Packets matched by nftables rules with a counter and a comment", "family", "table", "chain", "comment")

	ShardsF2bUp     = metric("shards_f2b_up", "1 if the fail2ban database could be read")
	ShardsF2bBanned = metric("shards_f2b_banned", "Number of currently banned IPs", "jail")
	ShardsF2bBans1h = metric("shards_f2b_bans_1h", "Number of bans issued during the last hour", "jail")
)
