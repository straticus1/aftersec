package modes

import (
	"log"
	"runtime"

	"aftersec/pkg/client/storage"
	"aftersec/pkg/exposure"
)

func publishExposure(mgr storage.Manager) {
	if mgr == nil {
		return
	}
	report := exposure.Collect(runtime.GOOS, exposure.CommandRunner)
	body, err := exposure.Marshal(report)
	if err != nil {
		log.Printf("exposure report rejected: %v", err)
		return
	}
	severity := "info"
	if report.Decision != exposure.Pass {
		severity = "high"
	}
	if err = mgr.LogTelemetryEvent("exposure", string(report.Decision), severity, string(body)); err != nil {
		log.Printf("exposure log failed: %v", err)
	}
}
