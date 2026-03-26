package rest

import (
	"aftersec/pkg/ai"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// BanditQueryRequest represents a user query to Bandit AI
type BanditQueryRequest struct {
	Query       string `json:"query" binding:"required"`
	TenantID    string `json:"tenant_id"`
	IncludeAll  bool   `json:"include_all"` // Include all telemetry or just relevant
}

// BanditQueryResponse represents Bandit AI's response
type BanditQueryResponse struct {
	Response    string                 `json:"response"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context,omitempty"`
	ProcessTime int64                  `json:"process_time_ms"`
}

// SystemTelemetry aggregates current system state for Bandit AI
type SystemTelemetry struct {
	Timestamp       time.Time              `json:"timestamp"`
	ProcessCount    int                    `json:"process_count"`
	NetworkConns    int                    `json:"network_connections"`
	RecentProcesses []ProcessInfo          `json:"recent_processes"`
	NetworkActivity []NetworkConnection    `json:"network_activity"`
	MemoryRegions   []MemoryRegion         `json:"memory_regions"`
	FirewallRules   []FirewallRule         `json:"firewall_rules"`
	UnifiedLogs     []LogEntry             `json:"unified_logs"`
	CustomData      map[string]interface{} `json:"custom_data"`
}

type ProcessInfo struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	User        string    `json:"user"`
	CPU         float64   `json:"cpu_percent"`
	Memory      uint64    `json:"memory_bytes"`
	StartTime   time.Time `json:"start_time"`
	Suspicious  bool      `json:"suspicious"`
}

type NetworkConnection struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
	Process    string `json:"process"`
	Protocol   string `json:"protocol"`
}

type MemoryRegion struct {
	Address     string `json:"address"`
	Size        uint64 `json:"size"`
	Permissions string `json:"permissions"`
	Process     string `json:"process"`
	Suspicious  bool   `json:"suspicious"`
}

type FirewallRule struct {
	Action  string `json:"action"`
	Source  string `json:"source"`
	Dest    string `json:"dest"`
	Proto   string `json:"proto"`
	Reason  string `json:"reason"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Process   string    `json:"process"`
	Category  string    `json:"category"`
	Message   string    `json:"message"`
	Level     string    `json:"level"`
}

// HandleBanditQuery processes a natural language query with system context
func HandleBanditQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()

	var req BanditQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Gather current system telemetry
	telemetry, err := gatherSystemTelemetry(req.IncludeAll)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to gather telemetry: %v", err)})
		return
	}

	// Convert telemetry to JSON for LLM context
	telemetryJSON, err := json.MarshalIndent(telemetry, "", "  ")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to marshal telemetry: %v", err)})
		return
	}

	// Query Bandit AI with full system context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	banditRequest := ai.BanditRequest{
		UserQuery:    req.Query,
		CurrentState: string(telemetryJSON),
	}

	response, err := ai.AskBandit(ctx, banditRequest)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Bandit AI failed: %v", err)})
		return
	}

	processTime := time.Since(startTime).Milliseconds()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(BanditQueryResponse{
		Response:    response,
		Timestamp:   time.Now(),
		ProcessTime: processTime,
		Context: map[string]interface{}{
			"telemetry_snapshot": telemetry,
		},
	})
}

// gatherSystemTelemetry collects current macOS system state
func gatherSystemTelemetry(includeAll bool) (*SystemTelemetry, error) {
	telemetry := &SystemTelemetry{
		Timestamp:    time.Now(),
		CustomData:   make(map[string]interface{}),
	}

	// Gather process information
	processes, err := getRunningProcesses()
	if err == nil {
		telemetry.RecentProcesses = processes
		telemetry.ProcessCount = len(processes)
	}

	// Gather network connections
	connections, err := getNetworkConnections()
	if err == nil {
		telemetry.NetworkActivity = connections
		telemetry.NetworkConns = len(connections)
	}

	// Gather suspicious memory regions (if requested)
	if includeAll {
		memoryRegions, err := getSuspiciousMemoryRegions()
		if err == nil {
			telemetry.MemoryRegions = memoryRegions
		}

		// Gather recent unified logs
		logs, err := getRecentUnifiedLogs()
		if err == nil {
			telemetry.UnifiedLogs = logs
		}

		// Gather firewall events
		fwRules, err := getRecentFirewallEvents()
		if err == nil {
			telemetry.FirewallRules = fwRules
		}
	}

	return telemetry, nil
}

// getRunningProcesses retrieves current processes using ps command
func getRunningProcesses() ([]ProcessInfo, error) {
	cmd := exec.Command("ps", "aux")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	processes := make([]ProcessInfo, 0, len(lines)-1)

	// Skip header line
	for i := 1; i < len(lines) && i < 20; i++ { // Limit to 20 most recent
		fields := strings.Fields(lines[i])
		if len(fields) < 11 {
			continue
		}

		var pid int
		fmt.Sscanf(fields[1], "%d", &pid)

		var cpu float64
		fmt.Sscanf(fields[2], "%f", &cpu)

		process := ProcessInfo{
			PID:  pid,
			User: fields[0],
			CPU:  cpu,
			Name: fields[10],
		}

		// Mark as suspicious if running from /tmp or high CPU
		if strings.Contains(process.Name, "/tmp/") || cpu > 80.0 {
			process.Suspicious = true
		}

		processes = append(processes, process)
	}

	return processes, nil
}

// getNetworkConnections retrieves active network connections
func getNetworkConnections() ([]NetworkConnection, error) {
	cmd := exec.Command("netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	connections := make([]NetworkConnection, 0)

	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED") || strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				conn := NetworkConnection{
					Protocol:   fields[0],
					LocalAddr:  fields[3],
					RemoteAddr: fields[4],
					State:      fields[5],
				}
				connections = append(connections, conn)

				if len(connections) >= 15 {
					break
				}
			}
		}
	}

	return connections, nil
}

// getSuspiciousMemoryRegions detects RWX memory regions (potential injection)
func getSuspiciousMemoryRegions() ([]MemoryRegion, error) {
	// This would integrate with pkg/forensics/memory.go
	// For now, return placeholder
	regions := []MemoryRegion{
		{
			Address:     "0x1405a0000",
			Size:        4096,
			Permissions: "rwx",
			Process:     "Electron",
			Suspicious:  true,
		},
	}

	return regions, nil
}

// getRecentUnifiedLogs retrieves recent security-relevant logs
func getRecentUnifiedLogs() ([]LogEntry, error) {
	cmd := exec.Command("log", "show", "--predicate", "category == 'security' OR subsystem == 'com.apple.authd'", "--last", "5m", "--style", "compact")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	logs := make([]LogEntry, 0)

	for _, line := range lines {
		if len(line) > 0 && len(logs) < 10 {
			logs = append(logs, LogEntry{
				Timestamp: time.Now(),
				Category:  "security",
				Message:   line,
				Level:     "info",
			})
		}
	}

	return logs, nil
}

// getRecentFirewallEvents retrieves firewall block events
func getRecentFirewallEvents() ([]FirewallRule, error) {
	// Placeholder - would integrate with actual firewall logs
	rules := []FirewallRule{
		{
			Action: "BLOCK",
			Source: "10.0.0.5",
			Dest:   "local",
			Proto:  "UDP/53",
			Reason: "Typosquatting C2 beacon (apple-update-metrics.xyz)",
		},
	}

	return rules, nil
}
