package modes

import (
	"log"

	"aftersec/pkg/client/storage"
	"aftersec/pkg/forensics"
)

func publishRootkit(mgr storage.Manager) {
	if mgr == nil {
		log.Printf("rootkit scan skipped: storage is unavailable")
		return
	}
	findings, err := forensics.InitRootkitDetector(mgr).PerformFullScan()
	if err != nil {
		log.Printf("rootkit view unavailable: %v", err)
		if logErr := mgr.LogTelemetryEvent("rootkit", "unavailable", "high", `{"result":"unavailable"}`); logErr != nil {
			log.Printf("rootkit log failed: %v", logErr)
		}
	}
	if len(findings) == 0 && err == nil {
		if logErr := mgr.LogTelemetryEvent("rootkit", "clear", "info", `{"findings":0}`); logErr != nil {
			log.Printf("rootkit log failed: %v", logErr)
		}
	}
}
