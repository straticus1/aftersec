//go:build linux

package forensics

import (
	"errors"
	"sync"
	"time"

	"aftersec/pkg/client/storage"
)

type RootkitFinding struct {
	DetectionType string
	Severity      string
	KEXTName      string
	KEXTPath      string
	ThreatScore   float64
	Evidence      map[string]interface{}
	Timestamp     time.Time
	Remediation   string
}

type RootkitDetector struct {
	mu   sync.RWMutex
	db   storage.Manager
}

var rootkitDetector *RootkitDetector
var rootkitOnce sync.Once

func InitRootkitDetector(db storage.Manager) *RootkitDetector {
	rootkitOnce.Do(func() {
		rootkitDetector = &RootkitDetector{db: db}
	})
	return rootkitDetector
}

func (rd *RootkitDetector) PerformFullScan() ([]RootkitFinding, error) {
	return nil, errors.New("kernel extension rootkit detection not available on Linux")
}
