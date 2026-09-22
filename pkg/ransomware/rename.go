package ransomware

import (
	"sync"
	"time"
)

// RenameWindow counts native rename events per PID inside a sliding window.
// Threats: bursty encrypt-and-rename ransomware is counted from sensor events;
// processes that rename without generating those events remain invisible.
type RenameWindow struct {
	mu     sync.Mutex
	window time.Duration
	events map[int][]time.Time
}

func NewRenameWindow(window time.Duration) *RenameWindow {
	return &RenameWindow{window: window, events: make(map[int][]time.Time)}
}

func (w *RenameWindow) Add(pid int, at time.Time) int {
	if w == nil || w.window <= 0 || pid <= 0 || at.IsZero() {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := at.Add(-w.window)
	kept := w.events[pid][:0]
	for _, seen := range w.events[pid] {
		if seen.After(cutoff) {
			kept = append(kept, seen)
		}
	}
	kept = append(kept, at)
	w.events[pid] = kept
	return len(kept)
}
