//go:build darwin

package forensics

import (
	"fmt"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

// PerformFullScan compares the kernel process table with ps, then lists loaded
// kernel extensions that are not Apple bundles. A failed view is an error.
func (rd *RootkitDetector) PerformFullScan() ([]RootkitFinding, error) {
	hidden, err := detectHiddenDarwin()
	if err != nil {
		return nil, err
	}
	kexts, err := detectForeignKexts()
	if err != nil {
		return hidden, err
	}
	findings := append(hidden, kexts...)
	if logErr := rd.record(findings); logErr != nil {
		return findings, logErr
	}
	return findings, nil
}

func detectHiddenDarwin() ([]RootkitFinding, error) {
	kernel, err := kernelPIDs()
	if err != nil {
		return nil, err
	}
	listed, err := listedPIDs()
	if err != nil {
		return nil, err
	}
	againKernel, err := kernelPIDs()
	if err != nil {
		return nil, err
	}
	againListed, err := listedPIDs()
	if err != nil {
		return nil, err
	}
	var findings []RootkitFinding
	for _, pid := range confirmedHidden(kernel, listed, againKernel, againListed) {
		findings = append(findings, RootkitFinding{
			DetectionType: "hidden_process",
			Severity:      "critical",
			ThreatScore:   0.95,
			Evidence: map[string]interface{}{
				"pid":             pid,
				"in_kernel_table": true,
				"in_process_list": false,
			},
			Timestamp:   time.Now(),
			Remediation: fmt.Sprintf("PID %d is in the kernel process table and missing from ps.", pid),
		})
	}
	return findings, nil
}

func kernelPIDs() (map[int]struct{}, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("kernel process view is unavailable")
	}
	pids := make(map[int]struct{}, len(procs))
	for _, proc := range procs {
		pid := int(proc.Proc.P_pid)
		if pid > 0 {
			pids[pid] = struct{}{}
		}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("kernel process view is empty")
	}
	return pids, nil
}

func listedPIDs() (map[int]struct{}, error) {
	out, err := exec.Command("/bin/ps", "-axo", "pid=").Output()
	if err != nil {
		return nil, fmt.Errorf("process list is unavailable")
	}
	return parsePIDLines(string(out))
}

func detectForeignKexts() ([]RootkitFinding, error) {
	out, err := exec.Command("/usr/sbin/kextstat").Output()
	if err != nil {
		return nil, fmt.Errorf("kext view is unavailable")
	}
	names, err := nonAppleKexts(string(out))
	if err != nil {
		return nil, err
	}
	var findings []RootkitFinding
	for _, name := range names {
		findings = append(findings, RootkitFinding{
			DetectionType: "foreign_kext",
			Severity:      "high",
			KEXTName:      name,
			ThreatScore:   0.8,
			Evidence: map[string]interface{}{
				"bundle": name,
			},
			Timestamp:   time.Now(),
			Remediation: "A loaded kernel extension is not an Apple bundle. Unload it only after confirming it is unexpected.",
		})
	}
	return findings, nil
}
