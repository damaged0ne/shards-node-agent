package promagent

import (
	"context"
	"errors"
	"net"
	"runtime"
	"time"

	commoncfg "github.com/prometheus/common/config"
	"github.com/vishvananda/netns"
	"k8s.io/klog/v2"
)

// HostNetnsDialer returns a dial function that connects from the host network namespace
// (the one of PID 1), so that containers on the host network are reachable at 127.0.0.1 and
// bridge networks at the container IPs even if the agent runs in its own network namespace.
// It returns nil if the agent already runs in the host network namespace.
func HostNetnsDialer(hostNsPath string) (commoncfg.DialContextFunc, error) {
	hostNs, err := netns.GetFromPath(hostNsPath)
	if err != nil {
		return nil, err
	}
	selfNs, err := netns.Get()
	if err != nil {
		_ = hostNs.Close()
		return nil, err
	}
	if hostNs.Equal(selfNs) {
		_ = hostNs.Close()
		_ = selfNs.Close()
		return nil, nil
	}
	// FallbackDelay < 0 disables Happy Eyeballs, so the socket is created in the calling goroutine
	// (on the locked thread) rather than in a helper goroutine.
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, FallbackDelay: -1}

	dialIn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		runtime.LockOSThread()
		if err := netns.Set(hostNs); err != nil {
			runtime.UnlockOSThread()
			return nil, err
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if rerr := netns.Set(selfNs); rerr != nil {
			// Keep the thread locked: it's terminated when the goroutine exits instead of being reused
			// in the wrong namespace.
			klog.Errorln("failed to restore the network namespace:", rerr)
			return conn, err
		}
		runtime.UnlockOSThread()
		return conn, err
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			return dialIn(ctx, network, addr)
		}
		// Resolve names from the agent's namespace, then connect to each address in turn.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var errs []error
		for _, ip := range ips {
			if network == "tcp4" && ip.IP.To4() == nil || network == "tcp6" && ip.IP.To4() != nil {
				continue
			}
			conn, err := dialIn(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
		}
		if len(errs) == 0 {
			return nil, &net.AddrError{Err: "no suitable address found", Addr: host}
		}
		return nil, errors.Join(errs...)
	}, nil
}
