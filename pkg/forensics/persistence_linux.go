//go:build linux

package forensics

import "errors"

type PersistenceFinding struct {
	PlistPath   string
	Program     string
	IsHidden    bool
	Authority   string
	ThreatScore ThreatScore
	Reason      string
}

func ScanPersistenceMechanisms() ([]PersistenceFinding, error) {
	return nil, errors.New("LaunchAgents/Daemons persistence scanning not available on Linux")
}
