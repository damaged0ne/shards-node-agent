//go:build linux

package shards

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
	_ "modernc.org/sqlite"
)

const f2bQueryTimeout = 5 * time.Second

type f2bCollector struct {
	dbPath string

	lock    sync.Mutex
	lastErr string
}

type f2bJail struct {
	banned int64
	bans1h int64
}

func (c *f2bCollector) collect(ch chan<- prometheus.Metric) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if _, err := os.Stat(c.dbPath); errors.Is(err, os.ErrNotExist) {
		// fail2ban isn't installed on this host
		return
	}
	jails, err := f2bRead(c.dbPath, time.Now())
	if err != nil {
		if s := err.Error(); s != c.lastErr {
			klog.Warningln("fail2ban:", s)
			c.lastErr = s
		}
		ch <- metrics.Gauge(metrics.ShardsF2bUp, 0)
		return
	}
	c.lastErr = ""
	ch <- metrics.Gauge(metrics.ShardsF2bUp, 1)
	for name, j := range jails {
		ch <- metrics.Gauge(metrics.ShardsF2bBanned, float64(j.banned), name)
		ch <- metrics.Gauge(metrics.ShardsF2bBans1h, float64(j.bans1h), name)
	}
}

// f2bRead reads ban statistics of the enabled jails from the fail2ban database (fail2ban >= 0.11).
func f2bRead(dbPath string, now time.Time) (map[string]*f2bJail, error) {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), f2bQueryTimeout)
	defer cancel()

	jails := map[string]*f2bJail{}
	rows, err := db.QueryContext(ctx, `SELECT name FROM jails WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		jails[name] = &f2bJail{}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// bips keeps the latest ban of each IP per jail, a negative bantime means a permanent ban
	err = f2bCountByJail(ctx, db, jails, func(j *f2bJail, n int64) { j.banned = n },
		`SELECT jail, count(*) FROM bips WHERE bantime < 0 OR timeofban + bantime > ? GROUP BY jail`, now.Unix())
	if err != nil {
		return nil, err
	}
	err = f2bCountByJail(ctx, db, jails, func(j *f2bJail, n int64) { j.bans1h = n },
		`SELECT jail, count(*) FROM bans WHERE timeofban > ? GROUP BY jail`, now.Add(-time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	return jails, nil
}

func f2bCountByJail(ctx context.Context, db *sql.DB, jails map[string]*f2bJail, set func(*f2bJail, int64), query string, args ...any) error {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var jail string
		var n int64
		if err = rows.Scan(&jail, &n); err != nil {
			return err
		}
		if j := jails[jail]; j != nil {
			set(j, n)
		}
	}
	return rows.Err()
}
