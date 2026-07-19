package fim

import (
	"context"
	"errors"
	"testing"
)

type failingWatcher struct{}

func (failingWatcher) Watch(context.Context, func(Event) error) error {
	return errors.New("watch denied")
}

func TestMonitorRejectsCriticalPathSymlinkEscape(t *testing.T) {
	m := NewMonitor([]string{"/etc/ssh", "/etc/sudoers"}, 1024)
	if err := m.ValidateEvent(Event{Path: "/etc/ssh/../passwd", WriterPID: 1}); !errors.Is(err, ErrOutsideCriticalPath) {
		t.Fatalf("ValidateEvent() error=%v", err)
	}
}

func TestMonitorRejectsUnattributedWrite(t *testing.T) {
	m := NewMonitor([]string{"/etc/ssh"}, 1024)
	if err := m.ValidateEvent(Event{Path: "/etc/ssh/sshd_config"}); !errors.Is(err, ErrMissingWriter) {
		t.Fatalf("ValidateEvent() error=%v", err)
	}
}

func TestMonitorBoundsBeforeAfterContent(t *testing.T) {
	m := NewMonitor([]string{"/etc/ssh"}, 4)
	err := m.ValidateEvent(Event{Path: "/etc/ssh/sshd_config", WriterPID: 1, Before: []byte("12345")})
	if !errors.Is(err, ErrContentTooLarge) {
		t.Fatalf("ValidateEvent() error=%v", err)
	}
}

func TestMonitorRequiredWatcherFailureIsReturned(t *testing.T) {
	m := NewMonitor([]string{"/etc/ssh"}, 1024)
	if err := m.Start(context.Background(), failingWatcher{}, true, func(Event) error { return nil }); err == nil {
		t.Fatal("expected required watcher failure")
	}
}
