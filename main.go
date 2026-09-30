package main

import (
	"bytes"
	"context"
	"flag"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coroot/coroot-node-agent/api"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/containers"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/host"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/node"
	"github.com/coroot/coroot-node-agent/node/metadata"
	"github.com/coroot/coroot-node-agent/profiling"
	"github.com/coroot/coroot-node-agent/prom"
	"github.com/coroot/coroot-node-agent/shards"
	"github.com/coroot/coroot-node-agent/tracing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

var (
	version = flags.Version
)

func uname() (string, string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	f, err := os.Open("/proc/1/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	self, err := os.Open("/proc/self/ns/uts")
	if err != nil {
		return "", "", err
	}
	defer self.Close()

	defer func() {
		unix.Setns(int(self.Fd()), unix.CLONE_NEWUTS)
	}()

	err = unix.Setns(int(f.Fd()), unix.CLONE_NEWUTS)
	if err != nil {
		return "", "", err
	}
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return "", "", err
	}
	hostname := string(bytes.Split(utsname.Nodename[:], []byte{0})[0])
	kernelVersion := string(bytes.Split(utsname.Release[:], []byte{0})[0])
	return hostname, kernelVersion, nil
}

func whitelistNodeExternalNetworks() {
	netdevs, err := node.NetDevices()
	if err != nil {
		klog.Warningln("failed to get network interfaces:", err)
		return
	}
	for _, iface := range netdevs {
		for _, p := range iface.IPPrefixes {
			if p.IP().IsLoopback() || common.IsIpPrivate(p.IP()) {
				continue
			}
			// if the node has an external network IP, whitelist that network
			common.ConnectionFilter.WhitelistPrefix(p)
		}
	}
}

// ready is set once the agent has initialized its core components (see /readyz).
var ready atomic.Bool

func initLogging() {
	// By default, klog writes a message to the output of its own severity and of every lower
	// severity (so a warning is written twice and an error four times when all severities share
	// one output), and additionally copies ERROR+ messages directly to stderr.
	// Write each message exactly once, through the rate-limited output.
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	for k, v := range map[string]string{
		"logtostderr":     "false",
		"alsologtostderr": "false",
		"one_output":      "true",
		"stderrthreshold": "4", // above FATAL: never write directly to stderr
	} {
		if err := fs.Set(k, v); err != nil {
			klog.Warningf("failed to set klog flag %s=%s: %s", k, v, err)
		}
	}
	klog.SetOutput(&RateLimitedLogOutput{limiter: rate.NewLimiter(rate.Limit(*flags.LogPerSecond), *flags.LogBurst)})
}

func newHttpMux(gatherer prometheus.Gatherer, registerer prometheus.Registerer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{ErrorLog: logger{}, Registry: registerer}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	if *flags.EnablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	return mux
}

func main() {
	initLogging()

	klog.Infoln("agent version:", version)

	hostname, kv, err := uname()
	if err != nil {
		klog.Exitln("failed to get uname:", err)
	}
	if *flags.HostnameOverride != "" {
		hostname = *flags.HostnameOverride
	}
	klog.Infoln("hostname:", hostname)
	klog.Infoln("kernel version:", kv)

	if err = common.SetKernelVersion(kv); err != nil {
		klog.Exitln(err)
	}

	if !common.GetKernelVersion().GreaterOrEqual(common.NewVersion(4, 16, 0)) {
		klog.Exitln("the minimum Linux kernel version required is 4.16 or later")
	}

	whitelistNodeExternalNetworks()

	machineId := host.MachineID()
	systemUuid := host.SystemUUID()

	tracing.Init(machineId, hostname, version)
	logs.Init(logs.Config{
		Endpoint:    *flags.LogsEndpoint,
		AuthHeaders: api.AuthHeaders(*flags.ApiKey),
		TLSConfig:   api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify),
	}, machineId, hostname, version)

	nodeCollector := node.NewCollector(hostname, kv, metadata.Overrides{
		Provider:          flags.GetString(flags.Provider),
		Region:            flags.GetString(flags.Region),
		AvailabilityZone:  flags.GetString(flags.AvailabilityZone),
		InstanceType:      flags.GetString(flags.InstanceType),
		InstanceLifeCycle: flags.GetString(flags.InstanceLifeCycle),
	})

	registry := prometheus.NewRegistry()

	registerer := prometheus.WrapRegistererWith(
		prometheus.Labels{"machine_id": machineId, "system_uuid": systemUuid},
		registry,
	)
	if err := registerer.Register(nodeCollector); err != nil {
		klog.Exitln(err)
	}

	gpuCollector, err := gpu.NewCollector()
	if err != nil {
		klog.Warningln("failed to initialize GPU collector:", err)
	}
	if err := registerer.Register(gpuCollector); err != nil {
		klog.Exitln(err)
	}
	registerer.MustRegister(info("node_agent_info", version))
	registerer.MustRegister(shards.NewCollector())
	if err := common.RegisterAgentMetrics(registerer); err != nil {
		klog.Exitln(err)
	}

	if md := nodeCollector.Metadata(); md != nil {
		region := md.Region
		az := md.AvailabilityZone
		if region != "" && az != "" {
			registerer = prometheus.WrapRegistererWith(prometheus.Labels{"az": az, "region": region}, registerer)
		}
	}
	processInfoCh, profilingCh := profiling.Init(machineId, hostname)
	cr, err := containers.NewRegistry(registerer, processInfoCh, profilingCh, gpuCollector.ProcessUsageSampleCh)
	if err != nil {
		klog.Exitln(err)
	}
	profiling.Start()

	if err := prom.StartAgent(registry, prom.Config{
		Endpoint:       *flags.MetricsEndpoint,
		AuthHeaders:    api.AuthHeaders(*flags.ApiKey),
		TLSConfig:      api.TlsConfig(*flags.CAFile, *flags.InsecureSkipVerify),
		ScrapeInterval: *flags.ScrapeInterval,
		WalDir:         *flags.WalDir,
		MaxSpoolSize:   int64(*flags.MaxSpoolSize),
	}, machineId, systemUuid); err != nil {
		klog.Exitln(err)
	}
	gatherer, stopShards := startShards(registry, registerer, hostname)
	ready.Store(true)

	klog.Infoln("listening on:", *flags.ListenAddress)

	srv := &http.Server{Addr: *flags.ListenAddress, Handler: newHttpMux(gatherer, registerer), ReadHeaderTimeout: 10 * time.Second}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.Exitln(err)
		}
	}()

	sig := <-sigCh
	klog.Infof("received %s, shutting down", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		klog.Warningf("HTTP server shutdown error: %s", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		shardsStopped := make(chan struct{})
		go func() {
			defer close(shardsStopped)
			stopShards()
		}()
		defer func() { <-shardsStopped }()
		cr.Close()
		profiling.Stop()
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer flushCancel()
		logs.Shutdown(flushCtx)
		tracing.Shutdown(flushCtx)
	}()

	select {
	case <-done:
		klog.Infoln("cleanup completed")
	case <-time.After(10 * time.Second):
		klog.Warningln("cleanup timed out, forcing exit")
	}
}

func info(name, version string) prometheus.Collector {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        name,
		ConstLabels: prometheus.Labels{"version": version},
	})
	g.Set(1)
	return g
}

type logger struct{}

func (l logger) Println(v ...interface{}) {
	klog.Errorln(v...)
}

type RateLimitedLogOutput struct {
	limiter *rate.Limiter
}

func (o *RateLimitedLogOutput) Write(data []byte) (int, error) {
	// ERROR and FATAL messages are never dropped (they used to bypass the limiter via klog's stderr threshold).
	if len(data) > 0 && (data[0] == 'E' || data[0] == 'F') {
		return os.Stderr.Write(data)
	}
	if !o.limiter.Allow() {
		return len(data), nil
	}
	return os.Stderr.Write(data)
}
