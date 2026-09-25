package agentinventory

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Command is one MCP server command declared in an agent config. Path is the
// executable name only. URL-only servers have an empty Path.
type Command struct {
	Agent string
	Name  string
	Path  string
}

// Declared reads MCP commands under home. A symlink, oversized file, or
// malformed config fails the whole read. A missing file is skipped. This is
// stricter than Findings, which records those cases as inventory findings.
func Declared(home string) ([]Command, error) {
	if strings.TrimSpace(home) == "" {
		return nil, errors.New("home unavailable")
	}
	var out []Command
	for _, spec := range configFiles {
		body, err := readRegular(filepath.Join(home, spec.rel))
		if err != nil {
			if errors.Is(err, errNotExist) {
				continue
			}
			return nil, fmt.Errorf("%s: %w", spec.rel, err)
		}
		servers, err := parse(spec.agent, body)
		if err != nil {
			return nil, fmt.Errorf("%s: malformed config", spec.rel)
		}
		for _, srv := range servers {
			out = append(out, Command{Agent: spec.agent, Name: srv.name, Path: srv.command})
			if len(out) >= maxServers {
				return out, nil
			}
		}
	}
	return out, nil
}
