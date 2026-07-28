package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"
	"time"

	"aftersec/pkg/selfprotect"
)

func main() {
	pidFile := flag.String("pid-file", "/var/run/aftersecd.pid", "protected agent PID file")
	agent := flag.String("agent", "/usr/local/sbin/aftersecd", "absolute protected agent binary")
	interval := flag.Duration("interval", 5*time.Second, "health check interval")
	misses := flag.Int("max-misses", 3, "consecutive misses before restart")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	watchdog := selfprotect.Watchdog{
		PIDFile: *pidFile, AgentPath: *agent, Args: flag.Args(),
		Interval: *interval, MaxMisses: *misses,
	}
	if err := watchdog.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("watchdog stopped: %v", err)
	}
}
