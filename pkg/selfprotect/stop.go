package selfprotect

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
)

var (
	ErrUnauthorizedStop   = errors.New("unauthorized agent stop")
	ErrEntitlementRevoked = errors.New("required agent entitlement revoked")
	ErrInvalidStopPolicy  = errors.New("invalid stop authorization policy")
)

// ClassifyStop denies launchctl/systemctl commands aimed at a protected unit
// or path. An empty argv is not a visible stop, so it is not treated as one.
//
// Threats: unload, bootout, stop, disable, and mask of the agent. This does
// not see a stop whose arguments the kernel event omitted.
func (g *Guard) ClassifyStop(argv []string) error {
	if g == nil {
		return ErrInvalidStopPolicy
	}
	if len(argv) == 0 {
		return nil
	}
	base := strings.ToLower(filepath.Base(argv[0]))
	if isShell(base) {
		text := strings.ToLower(strings.Join(argv, " "))
		if !containsStopVerb(text) || !strings.Contains(text, "aftersec") {
			return nil
		}
		if len(g.protected) == 0 {
			return ErrInvalidStopPolicy
		}
		return ErrUnauthorizedStop
	}
	if base != "launchctl" && base != "systemctl" {
		return nil
	}
	verb := ""
	if len(argv) > 1 {
		verb = strings.ToLower(argv[1])
	}
	switch verb {
	case "unload", "bootout", "stop", "disable", "mask":
	default:
		return nil
	}
	if len(g.protected) == 0 {
		return ErrInvalidStopPolicy
	}
	for _, arg := range argv[2:] {
		if g.protects(arg) || strings.Contains(strings.ToLower(arg), "aftersec") {
			return ErrUnauthorizedStop
		}
	}
	if len(argv) == 2 && strings.Contains(strings.ToLower(argv[1]), "aftersec") {
		return ErrUnauthorizedStop
	}
	return nil
}

// AuthorizeControllerExec denies a launchctl or systemctl exec aimed at
// this agent. A controller whose argument vector is missing or truncated
// is denied. Other programs are left to the caller.
//
// Threats: launchctl/systemctl stop verbs and shell -c wrappers that carry
// the same command. A stop hidden past the captured argument cap is outside
// what this process can see.
func (g *Guard) AuthorizeControllerExec(target string, argv []string, truncated bool) error {
	if g == nil {
		return ErrInvalidStopPolicy
	}
	controller := isController(target) || (len(argv) > 0 && isController(argv[0]))
	if !controller {
		return g.ClassifyStop(argv)
	}
	if truncated || len(argv) == 0 {
		return ErrUnauthorizedStop
	}
	return g.ClassifyStop(argv)
}

func isController(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "launchctl" || base == "systemctl"
}

func isShell(base string) bool {
	switch base {
	case "sh", "bash", "zsh", "dash":
		return true
	default:
		return false
	}
}

func containsStopVerb(text string) bool {
	for _, field := range strings.Fields(text) {
		switch strings.Trim(field, `"'`) {
		case "unload", "bootout", "stop", "disable", "mask":
			return true
		}
	}
	return false
}

func (g *Guard) AuthorizeStop(signerTrusted bool) error {
	if g == nil {
		return ErrInvalidStopPolicy
	}
	if !signerTrusted {
		return ErrUnauthorizedStop
	}
	return nil
}

func EntitlementsRevoked(required, observed []string) error {
	if len(required) == 0 {
		return ErrInvalidStopPolicy
	}
	have := make(map[string]struct{}, len(observed))
	for _, item := range observed {
		if item != "" {
			have[item] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for _, need := range required {
		if need == "" {
			return ErrInvalidStopPolicy
		}
		if _, ok := have[need]; !ok {
			missing = append(missing, need)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return ErrEntitlementRevoked
}
