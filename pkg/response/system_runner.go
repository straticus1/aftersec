package response

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"aftersec/pkg/breakglass"
	"aftersec/pkg/display"
	"aftersec/pkg/forensics"
	"aftersec/pkg/preserve"
)

// SystemActionRunner executes the narrow, signed live-response allowlist.
// Threats: unbounded file collection, symlink substitution, invalid process
// targets, and unauthorised quarantine release are rejected. Kernel compromise
// and permissions outside this process remain out of scope.
// DisplayCapturer is the user-session display process.
type DisplayCapturer interface {
	Capture(context.Context, int) ([]byte, error)
}

// StolenCamera arms the user-session camera after a stolen mark.
type StolenCamera interface {
	Arm(context.Context) error
	Disarm(context.Context) error
}

// Preserver uploads one evidence archive for a signed preserve mark.
type Preserver interface {
	Preserve(context.Context, string, string) error
}

type SystemActionRunner struct {
	quarantine *QuarantineManager
	maxBytes   int
	glass      *breakglass.Guard
	display    DisplayCapturer
	stolen     StolenCamera
	preserve   Preserver
}

func NewSystemActionRunner(quarantine *QuarantineManager, maxBytes int) *SystemActionRunner {
	return &SystemActionRunner{quarantine: quarantine, maxBytes: maxBytes}
}

func (r *SystemActionRunner) WithBreakGlass(g *breakglass.Guard) *SystemActionRunner {
	if r != nil {
		r.glass = g
	}
	return r
}

func (r *SystemActionRunner) WithDisplay(camera DisplayCapturer) *SystemActionRunner {
	if r != nil {
		r.display = camera
	}
	return r
}

func (r *SystemActionRunner) WithStolen(camera StolenCamera) *SystemActionRunner {
	if r != nil {
		r.stolen = camera
	}
	return r
}

func (r *SystemActionRunner) WithPreserve(p Preserver) *SystemActionRunner {
	if r != nil {
		r.preserve = p
	}
	return r
}

func (r *SystemActionRunner) Run(ctx context.Context, action Action, args map[string]string) ([]byte, error) {
	if r.maxBytes <= 0 {
		return nil, fmt.Errorf("system action runner is not safely configured")
	}
	switch action {
	case ActionQuarantine:
		if r.quarantine == nil {
			return nil, fmt.Errorf("quarantine is not configured")
		}
		port, err := strconv.ParseUint(args["port"], 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid control port")
		}
		if err := r.quarantine.Quarantine(ctx, ControlEndpoint{Host: args["host"], Port: uint16(port)}); err != nil {
			return nil, err
		}
		return []byte("quarantine active"), nil
	case ActionReleaseQuarantine:
		if r.quarantine == nil {
			return nil, fmt.Errorf("quarantine is not configured")
		}
		if err := r.quarantine.Release(ctx, true); err != nil {
			return nil, err
		}
		return []byte("quarantine released"), nil
	case ActionKillProcess:
		pid, err := parsePID(args["pid"])
		if err != nil {
			return nil, err
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			return nil, fmt.Errorf("terminate process: %w", err)
		}
		return []byte("process termination requested"), nil
	case ActionCollectFile:
		return r.collectFile(args["path"])
	case ActionReadMemory:
		pid, err := parsePID(args["pid"])
		if err != nil {
			return nil, err
		}
		findings, err := forensics.InitMemoryForensics(nil).ScanProcessMemory(pid)
		if err != nil {
			return nil, fmt.Errorf("scan process memory: %w", err)
		}
		return boundedJSON(findings, r.maxBytes)
	case ActionListPersistence:
		findings, err := forensics.ScanPersistenceMechanisms()
		if err != nil {
			return nil, fmt.Errorf("list persistence: %w", err)
		}
		return boundedJSON(findings, r.maxBytes)
	case ActionBreakGlass:
		if r.glass == nil {
			return nil, fmt.Errorf("break-glass is not configured")
		}
		d, err := breakglass.ParseDuration(args["duration"])
		if err != nil {
			return nil, err
		}
		if err := r.glass.Activate(time.Now().Add(d)); err != nil {
			return nil, err
		}
		return []byte("break-glass active"), nil
	case ActionDisplayShot:
		if len(args) != 0 {
			return nil, fmt.Errorf("display shot takes no arguments")
		}
		return r.captureDisplay(ctx, 0)
	case ActionDisplayRecord:
		seconds, err := ParseRecordSeconds(args)
		if err != nil {
			return nil, err
		}
		return r.captureDisplay(ctx, seconds)
	case ActionMarkStolen:
		if len(args) != 0 {
			return nil, fmt.Errorf("stolen mark takes no arguments")
		}
		if r.stolen == nil {
			return nil, fmt.Errorf("stolen camera is not configured")
		}
		if err := r.stolen.Arm(ctx); err != nil {
			return nil, err
		}
		return []byte("stolen mark armed"), nil
	case ActionClearStolen:
		if len(args) != 0 {
			return nil, fmt.Errorf("stolen mark takes no arguments")
		}
		if r.stolen == nil {
			return nil, fmt.Errorf("stolen camera is not configured")
		}
		if err := r.stolen.Disarm(ctx); err != nil {
			return nil, err
		}
		return []byte("stolen mark cleared"), nil
	case ActionPreserve:
		incident, reason, err := preserve.ParseMark(args)
		if err != nil {
			return nil, err
		}
		if r.preserve == nil {
			return nil, fmt.Errorf("preserve is not configured")
		}
		if err = r.preserve.Preserve(ctx, incident, reason); err != nil {
			return nil, err
		}
		return []byte("preserve stored"), nil
	case ActionClearPreserve:
		if len(args) != 0 {
			return nil, fmt.Errorf("preserve clear takes no arguments")
		}
		return []byte("preserve cleared"), nil
	default:
		return nil, fmt.Errorf("unsupported remote action")
	}
}

func (r *SystemActionRunner) captureDisplay(ctx context.Context, seconds int) ([]byte, error) {
	if r.display == nil {
		return nil, fmt.Errorf("display agent is not configured")
	}
	frame, err := r.display.Capture(ctx, seconds)
	if err != nil {
		return nil, err
	}
	out, err := display.Envelope(frame)
	if err != nil {
		return nil, err
	}
	if len(out) > r.maxBytes {
		return nil, fmt.Errorf("display frame exceeds limit")
	}
	return out, nil
}

func parsePID(raw string) (int, error) {
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("invalid process id")
	}
	return pid, nil
}

func (r *SystemActionRunner) collectFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("collection path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect collection path: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > int64(r.maxBytes) {
		return nil, fmt.Errorf("collection path is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open collection path: %w", err)
	}
	defer f.Close()
	data := make([]byte, info.Size()+1)
	n, err := f.Read(data)
	if err != nil {
		return nil, fmt.Errorf("read collection path: %w", err)
	}
	if n > r.maxBytes {
		return nil, fmt.Errorf("collected file exceeds limit")
	}
	return data[:n], nil
}

func boundedJSON(value any, max int) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode response: %w", err)
	}
	if len(data) > max {
		return nil, fmt.Errorf("response exceeds limit")
	}
	return data, nil
}
