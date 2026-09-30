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

	// Docker-level container metrics include exited containers, so container_id is a regular label here.
	ShardsContainerHealth        = metric("shards_container_health", "Docker healthcheck status of the container (series present with value 1 for the current status)", "container_id", "status")
	ShardsComposeInfo            = metric("shards_compose_info", "Docker Compose project and service of the container", "container_id", "project", "service")
	ShardsContainerState         = metric("shards_container_state", "Docker state of the container (series present with value 1 for the current state)", "container_id", "state")
	ShardsContainerExitCode      = metric("shards_container_exit_code", "Exit code of the last run of a container that isn't running", "container_id")
	ShardsContainerOOMKilled     = metric("shards_container_oom_killed", "1 if the last run of a container that isn't running was killed by the OOM killer", "container_id")
	ShardsContainerStarted       = metric("shards_container_started_seconds", "Unix time the container was last started", "container_id")
	ShardsContainerFinished      = metric("shards_container_finished_seconds", "Unix time the container last finished (only for containers that aren't running)", "container_id")
	ShardsContainerDockerRestart = metric("shards_container_docker_restarts", "Number of times dockerd restarted the container according to its restart policy", "container_id")
	ShardsContainerRestartPolicy = metric("shards_container_restart_policy", "Restart policy of the container", "container_id", "policy")
	ShardsContainerCreated       = metric("shards_container_created_seconds", "Unix time the container was created (Compose recreates containers on image or config changes)", "container_id")
	ShardsReleaseWindow          = metric("shards_release_window", "Present while the container is within the release window after it was (re)created, the value is the number of seconds left", "container_id", "version", "image_id")
	ShardsContainerImageInfo     = metric("shards_container_image_info", "Image of the container, version and revision come from the OCI image labels", "container_id", "image", "image_id", "version", "revision")

	ShardsNftCounterBytes   = metric("shards_nft_counter_bytes_total", "Bytes matched by a named nftables counter", "family", "table", "counter")
	ShardsNftCounterPackets = metric("shards_nft_counter_packets_total", "Packets matched by a named nftables counter", "family", "table", "counter")
	ShardsNftRuleBytes      = metric("shards_nft_rule_bytes_total", "Bytes matched by nftables rules with a counter and a comment", "family", "table", "chain", "comment")
	ShardsNftRulePackets    = metric("shards_nft_rule_packets_total", "Packets matched by nftables rules with a counter and a comment", "family", "table", "chain", "comment")

	ShardsF2bUp     = metric("shards_f2b_up", "1 if the fail2ban database could be read")
	ShardsF2bBanned = metric("shards_f2b_banned", "Number of currently banned IPs", "jail")
	ShardsF2bBans1h = metric("shards_f2b_bans_1h", "Number of bans issued during the last hour", "jail")
)
