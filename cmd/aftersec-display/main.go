package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"aftersec/pkg/display"
	"aftersec/pkg/stolendevice"
)

func main() {
	socket := flag.String("socket", os.Getenv("AFTERSEC_DISPLAY_SOCKET"), "absolute unix socket path")
	spool := flag.String("spool", os.Getenv("AFTERSEC_DISPLAY_SPOOL"), "private directory for recording frames")
	flag.Parse()
	if *socket == "" {
		log.Fatal("display socket path is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runner := &stolendevice.Runner{
		Camera:   stolendevice.CaptureCamera,
		Unlocked: stolendevice.SessionUnlocked,
		Spool:    *spool,
	}
	runner.Resume()
	agent := &display.Agent{
		Capturer: display.NewPlatformCapturer(),
		Spool:    *spool,
		Stolen: &display.StolenHooks{
			Arm: runner.Arm, Disarm: runner.Disarm, Next: runner.Next, Ack: runner.Ack,
		},
	}
	log.Print("aftersec-display listening for signed capture requests")
	if err := agent.Serve(ctx, *socket); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
