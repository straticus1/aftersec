// Package fim validates real-time critical-file integrity events.
//
// Threats: path traversal, symlink escapes, missing writer attribution, and
// oversized evidence are rejected. Platform watchers remain responsible for
// kernel event delivery and must fail startup when required watches cannot arm.
package fim

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

var (
	ErrOutsideCriticalPath = errors.New("path is outside critical integrity roots")
	ErrMissingWriter       = errors.New("file-integrity writer attribution missing")
	ErrContentTooLarge     = errors.New("file-integrity content exceeds limit")
	ErrInvalidEvent        = errors.New("invalid file-integrity event")
)

type Event struct {
	Path      string
	WriterPID int
	Before    []byte
	After     []byte
	Deleted   bool
}

type Monitor struct {
	roots      []string
	maxContent int
}

type Watcher interface {
	Watch(context.Context, func(Event) error) error
}

func NewMonitor(roots []string, maxContent int) *Monitor {
	clean := make([]string, 0, len(roots))
	for _, root := range roots {
		root = filepath.Clean(root)
		if filepath.IsAbs(root) {
			clean = append(clean, root)
		}
	}
	return &Monitor{roots: clean, maxContent: maxContent}
}

func (m *Monitor) ValidateEvent(event Event) error {
	if m.maxContent <= 0 || event.Path == "" || len(event.Path) > 4096 || event.WriterPID <= 0 {
		if event.WriterPID <= 0 {
			return ErrMissingWriter
		}
		return ErrInvalidEvent
	}
	path := filepath.Clean(event.Path)
	inside := false
	for _, root := range m.roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			inside = true
			break
		}
	}
	if !inside {
		return ErrOutsideCriticalPath
	}
	if len(event.Before) > m.maxContent || len(event.After) > m.maxContent {
		return ErrContentTooLarge
	}
	return nil
}

func (m *Monitor) Start(ctx context.Context, watcher Watcher, required bool, sink func(Event) error) error {
	if m == nil || watcher == nil || sink == nil || len(m.roots) == 0 || m.maxContent <= 0 {
		if required {
			return ErrInvalidEvent
		}
		return nil
	}
	err := watcher.Watch(ctx, func(event Event) error {
		if err := m.ValidateEvent(event); err != nil {
			return err
		}
		return sink(event)
	})
	if err != nil && required {
		return err
	}
	return err
}
