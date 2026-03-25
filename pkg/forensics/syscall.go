package forensics

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SyscallAlert struct {
	PID       int
	Command   string
	Pattern   string
	Score     ThreatScore
	Timestamp time.Time
}

type pidState struct {
	renameCount   int
	unlinkCount   int
	mprotectCount int
	ptraceCount   int
	lastSeen      time.Time
}

var stateMu sync.Mutex
var pidStates = make(map[int]*pidState)

// StartSyscallMonitor runs dtrace safely under macOS and parses the output
// for behavioral heuristics.
func StartSyscallMonitor(alertChan chan<- SyscallAlert) error {
	// The DTrace script
	script := `syscall::mprotect:entry, syscall::ptrace:entry, syscall::rename:entry, syscall::unlink:entry { printf("%d|%s|%s\n", pid, execname, probefunc); }`

	cmd := exec.Command("dtrace", "-q", "-n", script)
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	
	if err := cmd.Start(); err != nil {
		return err
	}

	go cleanupRoutine()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			continue
		}
		
		pidStr := strings.TrimSpace(parts[0])
		cmdName := strings.TrimSpace(parts[1])
		syscallName := strings.TrimSpace(parts[2])

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		
		// Avoid self-alerting
		if strings.Contains(cmdName, "aftersecd") || strings.Contains(cmdName, "aftersec-gui") || strings.Contains(cmdName, "dtrace") {
			continue
		}

		stateMu.Lock()
		st, exists := pidStates[pid]
		if !exists {
			st = &pidState{lastSeen: time.Now()}
			pidStates[pid] = st
		}
		st.lastSeen = time.Now()
		
		switch syscallName {
		case "rename":
			st.renameCount++
		case "unlink":
			st.unlinkCount++
		case "mprotect":
			st.mprotectCount++
		case "ptrace":
			st.ptraceCount++
		}
		
		// Heuristic 1: Ransomware/Wiper (Rapid rename + unlink)
		// More than 20 renames and unlinks combined in a recent window
		if st.renameCount + st.unlinkCount > 20 {
			alertChan <- SyscallAlert{
				PID:       pid,
				Command:   cmdName,
				Pattern:   "High-frequency file modification/deletion (Ransomware-like Wiper Behavior)",
				Score:     Malicious,
				Timestamp: time.Now(),
			}
			st.renameCount = 0
			st.unlinkCount = 0
		}
		
		// Heuristic 2: Injection (mprotect + ptrace)
		if st.mprotectCount > 10 || st.ptraceCount > 5 {
			alertChan <- SyscallAlert{
				PID:       pid,
				Command:   cmdName,
				Pattern:   "Repeated memory protection modifications or remote process attachments (Injection)",
				Score:     Suspicious,
				Timestamp: time.Now(),
			}
			st.mprotectCount = 0
			st.ptraceCount = 0
		}
		stateMu.Unlock()
	}

	return cmd.Wait()
}

func cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		stateMu.Lock()
		now := time.Now()
		for pid, st := range pidStates {
			if now.Sub(st.lastSeen) > 5*time.Second {
				// Reset counts if process was idle for 5 seconds to prevent slow accumulation false positives
				st.renameCount = 0
				st.unlinkCount = 0
				st.mprotectCount = 0
				st.ptraceCount = 0
			}
			if now.Sub(st.lastSeen) > 2*time.Minute {
				delete(pidStates, pid)
			}
		}
		stateMu.Unlock()
	}
}
