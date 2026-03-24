package forensics

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ScanRunningProcesses dumps the active local process map and executes YARA-like
// heuristic scans on the command and execution environment layers.
func ScanRunningProcesses() ([]ProcessFinding, error) {
	out, err := exec.Command("ps", "-eo", "pid,user,command", "-ww").CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	var anomalies []ProcessFinding

	for _, line := range lines[1:] { // skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		pidStr := parts[0]
		userStr := parts[1]
		cmdStr := strings.Join(parts[2:], " ")
		
		// Avoid flagging the scanner daemon or GUI
		if strings.Contains(cmdStr, "aftersec") || strings.Contains(cmdStr, "aftersecd") {
			continue
		}

		pid, _ := strconv.Atoi(pidStr)
		
		path, _ := GetProcessPath(pid)
		netCount, _ := GetOpenConnections(pid)
		
		score, reason := CheckSignature(cmdStr, path, netCount)

		if score > Safe {
			anomalies = append(anomalies, ProcessFinding{
				PID:         pid,
				User:        userStr,
				Command:     cmdStr,
				Path:        path,
				NetCount:    netCount,
				Score:       score,
				Reason:      reason,
				KillCommand: fmt.Sprintf("kill -9 %d", pid),
			})
		}
	}
	return anomalies, nil
}
