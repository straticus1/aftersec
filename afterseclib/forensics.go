package main

import (
	"aftersec/pkg/forensics"
)

// ScanProcesses runs a dynamic behavioral memory scan extracting indicators and evaluating ThreatScores.
func ScanProcesses() ([]forensics.ProcessFinding, error) {
	return forensics.ScanRunningProcesses(nil)
}

// ScanPersistenceMechanisms deeply evaluates the Plists in standard AutoStart directories.
func ScanPersistenceMechanisms() ([]forensics.PersistenceFinding, error) {
	return forensics.ScanPersistenceMechanisms()
}

// CheckEntitlements extracts the cryptographic components of an executable binary to evaluate injection risks.
func CheckEntitlements(binaryPath string) (forensics.EntitlementFinding, error) {
	return forensics.CheckEntitlements(binaryPath)
}

// TrainProcessBaseline takes a snapshot of current system memory and records the behaviors as "known good".
func TrainProcessBaseline() error {
	return forensics.TrainProcessBaseline()
}

// StartSyscallMonitor begins a continuous DTrace system call stream looking for injection & wiper behavior.
func StartSyscallMonitor(alertChan chan<- forensics.SyscallAlert) error {
	return forensics.StartSyscallMonitor(alertChan)
}
