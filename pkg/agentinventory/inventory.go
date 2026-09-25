// Package agentinventory inventories local AI coding agents and the MCP servers
// they are configured to launch.
//
// Threats: a config can hide a shell, an unpinned package runner (npx, uvx,
// docker), a cleartext remote server, or a secret in an env value or argument.
// This package never executes a configured command, never follows symlinks, and
// never copies env values into findings. An unreadable, oversized, or malformed
// config is a failed inventory, not a clean host. It does not see MCP servers
// that were started outside these files, and a passing local command is not a
// verdict that the agent is benign.
package agentinventory

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aftersec/pkg/core"
)

const (
	maxFileBytes = 1 << 20
	maxServers   = 256
	maxFindings  = 64
)

var (
	errNotExist   = errors.New("not found")
	errSymlink    = errors.New("symlink refused")
	errNotRegular = errors.New("not a regular file")
	errOversize   = errors.New("config exceeds 1 MiB")
	errMalformed  = errors.New("malformed config")

	secretKey = regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|credential)`)
	secretVal = regexp.MustCompile(`(?i)(sk-|sk-ant-|ghp_|github_pat_|xox[baprs]-|AKIA[0-9A-Z]{16}|-----BEGIN |Bearer )`)
	runners   = map[string]bool{
		"npx": true, "uvx": true, "bunx": true, "pip": true, "pipx": true,
		"docker": true, "curl": true, "wget": true,
	}
	shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "fish": true}
)

// configRoots are agent homes and MCP config files relative to the user home.
var configFiles = []struct {
	agent string
	rel   string
}{
	{"claude", ".claude.json"},
	{"claude", filepath.Join(".claude", "settings.json")},
	{"claude", filepath.Join(".claude", "mcp.json")},
	{"cursor", filepath.Join(".cursor", "mcp.json")},
	{"codex", filepath.Join(".codex", "config.toml")},
	{"vscode", filepath.Join(".config", "Code", "User", "mcp.json")},
	{"vscode", filepath.Join("Library", "Application Support", "Code", "User", "mcp.json")},
	{"goose", filepath.Join(".config", "goose", "config.yaml")},
	{"gemini", filepath.Join(".gemini", "settings.json")},
}

// Findings scans home for coding-agent MCP configuration. home is the directory
// that contains the agent config files. Callers pass the real user home in
// production and a temp directory in tests.
func Findings(home string) []core.Finding {
	if strings.TrimSpace(home) == "" {
		return []core.Finding{failed("AI agent inventory", "home unavailable", "the user home directory could not be resolved")}
	}
	var out []core.Finding
	seen := 0
	add := func(f core.Finding) {
		if len(out) >= maxFindings {
			return
		}
		out = append(out, f)
	}
	for _, spec := range configFiles {
		if seen >= maxServers {
			add(failed("AI agent inventory", "server cap", "stopped after 256 MCP servers"))
			break
		}
		path := filepath.Join(home, spec.rel)
		body, err := readRegular(path)
		if err != nil {
			if errors.Is(err, errNotExist) {
				continue
			}
			add(failed(spec.agent+" config", filepath.Base(spec.rel), err.Error()))
			continue
		}
		servers, err := parse(spec.agent, body)
		if err != nil {
			add(failed(spec.agent+" config", filepath.Base(spec.rel), "malformed config"))
			continue
		}
		for _, srv := range servers {
			seen++
			add(srv.finding())
			if seen >= maxServers {
				break
			}
		}
	}
	if len(out) == 0 {
		add(core.Finding{
			Category:    "Agentic Endpoint",
			Name:        "AI agent inventory",
			Description: "No local coding-agent or MCP config was present in the known paths.",
			Severity:    core.LogOnly,
			CurrentVal:  "none observed",
			ExpectedVal: "known local agents only",
			Passed:      true,
		})
	}
	return out
}

type server struct {
	agent   string
	name    string
	command string
	url     string
	secret  bool
	reasons []string
	passed  bool
	sev     core.Severity
}

func (s server) finding() core.Finding {
	current := "local command"
	if s.url != "" {
		current = s.url
	} else if s.command != "" {
		current = s.command
	}
	if s.secret {
		current += " (secret env key present, value withheld)"
	}
	return core.Finding{
		Category:    "Agentic Endpoint",
		Name:        "MCP server " + s.agent + "/" + s.name,
		Description: "Coding-agent MCP server declared on this host. The command was not executed.",
		Severity:    s.sev,
		CurrentVal:  current,
		ExpectedVal: "local pinned command, no secret env, no cleartext URL",
		LogContext:  strings.Join(s.reasons, "; "),
		Passed:      s.passed,
	}
}

func failed(name, current, why string) core.Finding {
	return core.Finding{
		Category:    "Agentic Endpoint",
		Name:        name,
		Description: "Agent inventory could not vouch for this config.",
		Severity:    core.High,
		CurrentVal:  current,
		ExpectedVal: "readable regular file under 1 MiB",
		LogContext:  why,
		Passed:      false,
	}
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNotExist
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if info.Size() > maxFileBytes {
		return nil, errOversize
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxFileBytes {
		return nil, errOversize
	}
	return body, nil
}

func parse(agent string, body []byte) ([]server, error) {
	trim := strings.TrimSpace(string(body))
	if trim == "" {
		return nil, errMalformed
	}
	if strings.Contains(trim, "[mcp_servers.") || strings.Contains(trim, "[mcp_servers]") {
		return parseTOML(agent, string(body))
	}
	if trim[0] == '{' || trim[0] == '[' {
		return parseJSON(agent, body)
	}
	return parseYAMLLoose(agent, string(body))
}

func parseJSON(agent string, body []byte) ([]server, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errMalformed
	}
	raw, ok := doc["mcpServers"]
	if !ok {
		raw = doc["mcp_servers"]
	}
	if raw == nil {
		return nil, nil
	}
	var servers map[string]mcpServer
	if err := json.Unmarshal(raw, &servers); err != nil {
		return nil, errMalformed
	}
	return classifyMap(agent, servers), nil
}

type mcpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
}

func classifyMap(agent string, servers map[string]mcpServer) []server {
	out := make([]server, 0, len(servers))
	for name, raw := range servers {
		out = append(out, classify(agent, clip(name, 128), raw))
	}
	return out
}

func classify(agent, name string, raw mcpServer) server {
	s := server{agent: agent, name: name, command: base(raw.Command), url: clip(raw.URL, 256), passed: true, sev: core.Low}
	if s.name == "" {
		s.name = "unnamed"
	}
	switch {
	case strings.HasPrefix(strings.ToLower(s.url), "http://"):
		s.passed = false
		s.sev = core.Critical
		s.reasons = append(s.reasons, "cleartext MCP URL")
	case strings.HasPrefix(strings.ToLower(s.url), "https://"):
		s.passed = false
		s.sev = core.Med
		s.reasons = append(s.reasons, "remote MCP server")
	}
	cmd := strings.ToLower(s.command)
	switch {
	case shells[cmd]:
		s.passed = false
		s.sev = core.Critical
		s.reasons = append(s.reasons, "shell launcher")
	case runners[cmd]:
		s.passed = false
		if s.sev != core.Critical {
			s.sev = core.High
		}
		s.reasons = append(s.reasons, "unpinned package runner")
	}
	for key := range raw.Env {
		if secretKey.MatchString(key) {
			s.secret = true
			s.passed = false
			if s.sev != core.Critical {
				s.sev = core.High
			}
			s.reasons = append(s.reasons, "secret env key "+clip(key, 64))
			break
		}
	}
	for _, arg := range raw.Args {
		if secretVal.MatchString(arg) {
			s.secret = true
			s.passed = false
			if s.sev != core.Critical {
				s.sev = core.High
			}
			s.reasons = append(s.reasons, "secret-like argument withheld")
			break
		}
	}
	if s.passed {
		s.reasons = append(s.reasons, "local command, not executed")
	}
	return s
}

func parseTOML(agent, body string) ([]server, error) {
	var current string
	servers := map[string]mcpServer{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			header := strings.Trim(line, "[]")
			if rest, ok := strings.CutPrefix(header, "mcp_servers."); ok && rest != "" && !strings.Contains(rest, ".") {
				current = rest
				if _, exists := servers[current]; !exists {
					servers[current] = mcpServer{}
				}
			} else {
				current = ""
			}
			continue
		}
		if current == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errMalformed
		}
		srv := servers[current]
		switch strings.TrimSpace(key) {
		case "command":
			srv.Command = unquote(strings.TrimSpace(val))
		case "url":
			srv.URL = unquote(strings.TrimSpace(val))
		case "args":
			srv.Args = splitList(unquote(strings.TrimSpace(val)))
		default:
		}
		servers[current] = srv
	}
	if len(servers) == 0 && strings.Contains(body, "=") && !strings.Contains(body, "[mcp_servers.") {
		return nil, errMalformed
	}
	return classifyMap(agent, servers), nil
}

func parseYAMLLoose(agent, body string) ([]server, error) {
	// Goose-style "name:" blocks with cmd/command/url. A file that is not a
	// map of those keys and is not empty is malformed.
	var current string
	servers := map[string]mcpServer{}
	interesting := false
	for _, line := range strings.Split(body, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trim, ":") {
			current = strings.TrimSuffix(trim, ":")
			continue
		}
		key, val, ok := strings.Cut(trim, ":")
		if !ok || current == "" {
			continue
		}
		key = strings.TrimSpace(key)
		val = unquote(strings.TrimSpace(val))
		if key == "cmd" || key == "command" || key == "url" {
			interesting = true
			srv := servers[current]
			switch key {
			case "cmd", "command":
				srv.Command = val
			case "url":
				srv.URL = val
			}
			servers[current] = srv
		}
	}
	if !interesting {
		return nil, errMalformed
	}
	return classifyMap(agent, servers), nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return strings.Trim(s, "[] ")
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = unquote(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func base(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	return filepath.Base(command)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
