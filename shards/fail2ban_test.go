//go:build linux

package shards

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// schema of fail2ban 0.11+ (fail2ban/server/database.py)
const f2bSchema = `
CREATE TABLE fail2banDb(version INTEGER);
CREATE TABLE jails(name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE logs(jail TEXT NOT NULL, path TEXT, firstlinemd5 TEXT, lastfilepos INTEGER DEFAULT 0);
CREATE TABLE bans(jail TEXT NOT NULL, ip TEXT, timeofban INTEGER NOT NULL, bantime INTEGER NOT NULL, bancount INTEGER NOT NULL default 1, data JSON);
CREATE INDEX bans_jail_timeofban_ip ON bans(jail, timeofban);
CREATE TABLE bips(ip TEXT NOT NULL, jail TEXT NOT NULL, timeofban INTEGER NOT NULL, bantime INTEGER NOT NULL, bancount INTEGER NOT NULL default 1, data JSON, PRIMARY KEY(ip, jail));
`

func TestF2bRead(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "fail2ban.sqlite3")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec(f2bSchema)
	require.NoError(t, err)
	ts := now.Unix()
	for _, q := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO jails VALUES ('sshd', 1), ('nginx', 1), ('old', 0)`, nil},
		{`INSERT INTO bips VALUES
			('1.1.1.1', 'sshd', ?, 600, 1, '{}'),
			('2.2.2.2', 'sshd', ?, 600, 1, '{}'),
			('3.3.3.3', 'sshd', ?, -1, 3, '{}'),
			('4.4.4.4', 'old', ?, 600, 1, '{}')`,
			[]any{ts - 60 /* active */, ts - 3600 /* expired */, ts - 86400*30 /* permanent */, ts - 60 /* disabled jail */}},
		{`INSERT INTO bans VALUES
			('sshd', '1.1.1.1', ?, 600, 1, '{}'),
			('sshd', '2.2.2.2', ?, 600, 1, '{}'),
			('nginx', '5.5.5.5', ?, 600, 1, '{}')`,
			[]any{ts - 60, ts - 7200, ts - 10}},
	} {
		_, err = db.Exec(q.query, q.args...)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())

	jails, err := f2bRead(path, now)
	require.NoError(t, err)
	assert.Equal(t, map[string]*f2bJail{
		"sshd":  {banned: 2, bans1h: 1},
		"nginx": {banned: 0, bans1h: 1},
	}, jails)
}

func collectAll(f func(ch chan<- prometheus.Metric)) []prometheus.Metric {
	ch := make(chan prometheus.Metric, 100)
	f(ch)
	close(ch)
	var res []prometheus.Metric
	for m := range ch {
		res = append(res, m)
	}
	return res
}

func TestF2bCollectorNoDatabase(t *testing.T) {
	c := &f2bCollector{dbPath: filepath.Join(t.TempDir(), "missing.sqlite3")}
	assert.Empty(t, collectAll(c.collect))
}

func TestF2bCollectorBrokenDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fail2ban.sqlite3")
	require.NoError(t, os.WriteFile(path, []byte("not a database"), 0644))
	c := &f2bCollector{dbPath: path}
	ms := collectAll(c.collect)
	require.Len(t, ms, 1)
	assert.Contains(t, ms[0].Desc().String(), "shards_f2b_up")
	assert.Equal(t, 0., gaugeValue(t, ms[0]))
}
