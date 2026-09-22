package ransomware

import (
	"testing"
	"time"
)

func TestRenameWindowCountsWithinWindowOnly(t *testing.T) {
	w := NewRenameWindow(time.Minute)
	now := time.Unix(1000, 0)
	if got := w.Add(42, now); got != 1 {
		t.Fatal(got)
	}
	if got := w.Add(42, now.Add(30*time.Second)); got != 2 {
		t.Fatal(got)
	}
	if got := w.Add(42, now.Add(2*time.Minute)); got != 1 {
		t.Fatal(got)
	}
	if got := w.Add(0, now); got != 0 {
		t.Fatal(got)
	}
}
