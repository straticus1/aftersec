//go:build linux

package forensics

import (
	"errors"
	"sync"
	"time"

	"aftersec/pkg/client/storage"
)

type MemoryRegion struct {
	StartAddress uint64
	EndAddress   uint64
	Size         uint64
	Permissions  string
	Path         string
}

type MemoryFinding struct {
	PID         int
	ProcessName string
	ProcessPath string
	FindingType string
	ThreatScore float64
	MemoryRegion string
	Indicators  map[string]interface{}
	Timestamp   time.Time
	Remediation string
}

type MemoryPattern struct {
	Name        string
	Pattern     []byte
	Description string
	Severity    string
	ThreatScore float64
}

type MemoryForensicsEngine struct {
	mu sync.RWMutex
	db storage.Manager
}

var memoryForensicsEngine *MemoryForensicsEngine
var memoryForensicsOnce sync.Once

func InitMemoryForensics(db storage.Manager) *MemoryForensicsEngine {
	memoryForensicsOnce.Do(func() {
		memoryForensicsEngine = &MemoryForensicsEngine{db: db}
	})
	return memoryForensicsEngine
}

func (mf *MemoryForensicsEngine) ScanProcessMemory(_ int) ([]MemoryFinding, error) {
	return nil, errors.New("process memory forensics not implemented on Linux")
}
