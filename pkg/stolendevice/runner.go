package stolendevice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"aftersec/pkg/display"
)

// Runner stores camera frames for a stolen, unlocked endpoint.
type Runner struct {
	Camera   func(context.Context) ([]byte, error)
	Unlocked func(context.Context) (bool, error)
	Spool    string
	Guard    *Guard
	mu       sync.Mutex
	cancel   context.CancelFunc
}

func (r *Runner) Arm() error {
	if r == nil || r.Camera == nil || r.Unlocked == nil || r.Spool == "" {
		return fmt.Errorf("stolen camera is not configured")
	}
	if r.Guard == nil {
		r.Guard = NewGuard()
	}
	dir := filepath.Join(r.Spool, "stolen")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create stolen photo directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("protect stolen photo directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "armed"), []byte("stolen\n"), 0600); err != nil {
		return fmt.Errorf("record stolen mark: %w", err)
	}
	r.Guard.Arm()
	r.mu.Lock()
	if r.cancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		r.cancel = cancel
		go r.loop(ctx)
	}
	r.mu.Unlock()
	return nil
}

func (r *Runner) Disarm() error {
	if r == nil || r.Guard == nil {
		return fmt.Errorf("stolen camera is not configured")
	}
	r.Guard.Disarm()
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.mu.Unlock()
	if r.Spool != "" {
		os.Remove(filepath.Join(r.Spool, "stolen", "armed"))
	}
	return nil
}

func (r *Runner) Resume() {
	if r == nil || r.Spool == "" {
		return
	}
	if _, err := os.Stat(filepath.Join(r.Spool, "stolen", "armed")); err == nil {
		_ = r.Arm()
	}
}

func (r *Runner) loop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.Poll(ctx, time.Now())
		}
	}
}

// Poll takes one photo when the guard allows it. The delay is waited here
// unless the context ends, which covers disarm and shutdown.
func (r *Runner) Poll(ctx context.Context, now time.Time) error {
	if r == nil || r.Guard == nil || r.Unlocked == nil || r.Camera == nil {
		return fmt.Errorf("stolen camera is not configured")
	}
	unlocked, err := r.Unlocked(ctx)
	if err != nil {
		return err
	}
	delay, err := r.Guard.Delay(now, unlocked)
	if err != nil {
		return err
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	frame, err := r.Camera(ctx)
	if err != nil {
		return err
	}
	fitted, err := display.FitJPEG(frame)
	if err != nil {
		return err
	}
	return r.store(fitted, time.Now())
}

func (r *Runner) store(frame []byte, now time.Time) error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fmt.Errorf("stolen photo id: %w", err)
	}
	name := hex.EncodeToString(id[:])
	dir := filepath.Join(r.Spool, "stolen")
	if err := r.trim(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, name+".jpg")
	if err := os.WriteFile(path, frame, 0600); err != nil {
		return fmt.Errorf("store stolen photo: %w", err)
	}
	r.Guard.Mark(now)
	return nil
}

func (r *Runner) trim(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, "*.jpg"))
	if err != nil {
		return err
	}
	sort.Strings(matches)
	for len(matches) >= MaxStored {
		if err = os.Remove(matches[0]); err != nil {
			return fmt.Errorf("remove old stolen photo: %w", err)
		}
		matches = matches[1:]
	}
	return nil
}

// Next returns the oldest stored photo. An empty id means there is nothing to send.
func (r *Runner) Next() (string, []byte, error) {
	if r == nil || r.Spool == "" {
		return "", nil, fmt.Errorf("stolen camera is not configured")
	}
	matches, err := filepath.Glob(filepath.Join(r.Spool, "stolen", "*.jpg"))
	if err != nil {
		return "", nil, err
	}
	sort.Strings(matches)
	if len(matches) == 0 {
		return "", nil, nil
	}
	name := strings.TrimSuffix(filepath.Base(matches[0]), ".jpg")
	if !photoID(name) {
		return "", nil, fmt.Errorf("stolen photo identity is invalid")
	}
	frame, err := os.ReadFile(matches[0])
	if err != nil {
		return "", nil, err
	}
	return name, frame, nil
}

// Ack removes a photo after the server has stored it.
func (r *Runner) Ack(id string) error {
	if r == nil || r.Spool == "" || !photoID(id) {
		return fmt.Errorf("stolen photo identity is invalid")
	}
	path := filepath.Join(r.Spool, "stolen", id+".jpg")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func photoID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
