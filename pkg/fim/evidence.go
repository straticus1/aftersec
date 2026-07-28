package fim

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type pendingEvidence struct {
	path   string
	before []byte
}

type EvidenceCapture struct {
	mu         sync.Mutex
	maxContent int
	capacity   int
	pending    map[string]pendingEvidence
}

func NewEvidenceCapture(maxContent, capacity int) *EvidenceCapture {
	return &EvidenceCapture{
		maxContent: maxContent, capacity: capacity,
		pending: make(map[string]pendingEvidence),
	}
}

func (c *EvidenceCapture) Begin(pid int, path string) error {
	if c == nil || pid <= 0 || !filepath.IsAbs(path) || c.maxContent <= 0 || c.capacity <= 0 {
		return ErrInvalidEvent
	}
	before, err := readEvidence(path, c.maxContent)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	key := evidenceKey(pid, filepath.Clean(path))
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.pending[key]; !exists && len(c.pending) >= c.capacity {
		return fmt.Errorf("file-integrity evidence capacity reached")
	}
	c.pending[key] = pendingEvidence{path: filepath.Clean(path), before: before}
	return nil
}

func (c *EvidenceCapture) Complete(pid int, path string) (Event, error) {
	if c == nil || pid <= 0 || !filepath.IsAbs(path) {
		return Event{}, ErrInvalidEvent
	}
	clean := filepath.Clean(path)
	key := evidenceKey(pid, clean)
	c.mu.Lock()
	pending, ok := c.pending[key]
	if ok {
		delete(c.pending, key)
	}
	c.mu.Unlock()
	if !ok {
		return Event{}, fmt.Errorf("missing before-write evidence")
	}
	after, err := readEvidence(clean, c.maxContent)
	deleted := os.IsNotExist(err)
	if err != nil && !deleted {
		return Event{}, err
	}
	return Event{
		Path: clean, WriterPID: pid, Before: pending.before, After: after, Deleted: deleted,
	}, nil
}

func (c *EvidenceCapture) Cancel(pid int, path string) {
	if c == nil || pid <= 0 || !filepath.IsAbs(path) {
		return
	}
	c.mu.Lock()
	delete(c.pending, evidenceKey(pid, filepath.Clean(path)))
	c.mu.Unlock()
}

func readEvidence(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidEvent
	}
	if info.Size() > int64(limit) {
		return nil, ErrContentTooLarge
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, ErrContentTooLarge
	}
	return data, nil
}

func evidenceKey(pid int, path string) string { return fmt.Sprintf("%d\x00%s", pid, path) }
