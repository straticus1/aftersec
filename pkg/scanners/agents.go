package scanners

import (
	"os"

	"aftersec/pkg/agentinventory"
	"aftersec/pkg/core"
)

// ScanAgentSurface records local coding agents and MCP servers. A missing home
// directory is a failed finding. The inventory never launches those servers.
func ScanAgentSurface(addFinding func(core.Finding)) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		addFinding(core.Finding{
			Category:    "Agentic Endpoint",
			Name:        "AI agent inventory",
			Description: "Agent inventory could not resolve the user home.",
			Severity:    core.High,
			CurrentVal:  "home unavailable",
			ExpectedVal: "readable user home",
			Passed:      false,
		})
		return
	}
	for _, finding := range agentinventory.Findings(home) {
		addFinding(finding)
	}
}
