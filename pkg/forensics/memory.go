package forensics

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

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
		
		behaviorScore, behaviorReason := AnalyzeBehavior(cmdStr, path, netCount)
		if behaviorScore > score {
			score = behaviorScore
		}
		if behaviorReason != "" {
			if reason != "" {
				reason += " | " + behaviorReason
			} else {
				reason = behaviorReason
			}
		}
		
		if path != "" {
			entFinding, _ := CheckEntitlements(path)
			if entFinding.ThreatScore > score {
				score = entFinding.ThreatScore
			}
			if entFinding.Reason != "" {
				if reason != "" {
					reason += " | " + entFinding.Reason
				} else {
					reason = entFinding.Reason
				}
			}
		}

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
		} else {
			RecordBehavior(cmdStr, path, netCount)
		}
	}
	
	SaveBehaviorDB()
	return anomalies, nil
}

func TrainProcessBaseline() error {
	out, err := exec.Command("ps", "-eo", "pid,user,command", "-ww").CombinedOutput()
	if err != nil {
		return err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" { continue }

		parts := strings.Fields(line)
		if len(parts) < 3 { continue }

		cmdStr := strings.Join(parts[2:], " ")
		if strings.Contains(cmdStr, "aftersec") || strings.Contains(cmdStr, "aftersecd") {
			continue
		}

		pidStr := parts[0]
		pid, _ := strconv.Atoi(pidStr)
		
		path, _ := GetProcessPath(pid)
		netCount, _ := GetOpenConnections(pid)
		
		// Only track things that don't match static signatures
		score, _ := CheckSignature(cmdStr, path, netCount)
		if score == Safe {
		    RecordBehavior(cmdStr, path, netCount)
		}
	}
	SaveBehaviorDB()
	return nil
}
