package display

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"time"
)

// Capturer takes one display frame. Platform implementations use a fixed
// command line. Callers cannot supply arguments.
type Capturer interface {
	Frame(context.Context) ([]byte, error)
}

// FramePlan chooses how many samples fit in a bounded recording.
func FramePlan(seconds int) (frames int, gap time.Duration, err error) {
	if seconds < 1 || seconds > MaxRecordSeconds {
		return 0, 0, fmt.Errorf("display recording must be between 1 and 60 seconds")
	}
	frames = seconds
	if frames > 12 {
		frames = 12
	}
	if frames == 1 {
		return 1, 0, nil
	}
	gap = time.Duration(seconds) * time.Second / time.Duration(frames-1)
	if gap < time.Second {
		gap = time.Second
	}
	return frames, gap, nil
}

// Record samples the display and returns one contact-sheet JPEG.
// When spool is set, each fitted frame is also kept in a private directory.
func Record(ctx context.Context, camera Capturer, seconds int, spool string, sleep func(context.Context, time.Duration) error) ([]byte, error) {
	if camera == nil {
		return nil, fmt.Errorf("display capturer is not configured")
	}
	frames, gap, err := FramePlan(seconds)
	if err != nil {
		return nil, err
	}
	if sleep == nil {
		sleep = sleepContext
	}
	var session string
	if spool != "" {
		var id [8]byte
		if _, err = rand.Read(id[:]); err != nil {
			return nil, fmt.Errorf("display recording id: %w", err)
		}
		session = filepath.Join(spool, "record-"+hex.EncodeToString(id[:]))
		if err = os.Mkdir(session, 0700); err != nil {
			return nil, fmt.Errorf("create display recording: %w", err)
		}
	}
	fitted := make([][]byte, 0, frames)
	failed := true
	if session != "" {
		defer func() {
			if failed {
				os.RemoveAll(session)
			}
		}()
	}
	for i := 0; i < frames; i++ {
		if i > 0 {
			if err = sleep(ctx, gap); err != nil {
				return nil, err
			}
		}
		raw, err := camera.Frame(ctx)
		if err != nil {
			return nil, err
		}
		frame, err := FitJPEG(raw)
		if err != nil {
			return nil, err
		}
		if session != "" {
			path := filepath.Join(session, fmt.Sprintf("frame-%02d.jpg", i))
			if err = os.WriteFile(path, frame, 0600); err != nil {
				return nil, fmt.Errorf("store display frame: %w", err)
			}
		}
		fitted = append(fitted, frame)
	}
	sheet, err := contactSheet(fitted)
	if err != nil {
		return nil, err
	}
	failed = false
	return sheet, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func contactSheet(frames [][]byte) ([]byte, error) {
	if len(frames) == 0 {
		return nil, fmt.Errorf("display recording has no frames")
	}
	const thumbW, thumbH, cols = 160, 90, 4
	rows := (len(frames) + cols - 1) / cols
	canvas := image.NewRGBA(image.Rect(0, 0, cols*thumbW, rows*thumbH))
	for i, frame := range frames {
		img, err := jpeg.Decode(bytes.NewReader(frame))
		if err != nil {
			return nil, fmt.Errorf("display recording frame is not a jpeg")
		}
		cell := scale(img, thumbW, thumbH)
		ox := (i % cols) * thumbW
		oy := (i / cols) * thumbH
		cb := cell.Bounds()
		for y := 0; y < cb.Dy() && y < thumbH; y++ {
			for x := 0; x < cb.Dx() && x < thumbW; x++ {
				canvas.Set(ox+x, oy+y, cell.At(cb.Min.X+x, cb.Min.Y+y))
			}
		}
	}
	for _, quality := range []int{70, 50, 30} {
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, canvas, &jpeg.Options{Quality: quality}); err != nil {
			return nil, fmt.Errorf("encode display recording: %w", err)
		}
		if buf.Len() <= MaxJPEG && ValidateJPEG(buf.Bytes()) == nil {
			return buf.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("display recording exceeds limit")
}
