// Package display captures one screen or a short recording from a
// user-session process. The system daemon never captures the display itself.
//
// Threats: a missing permission, a non-root caller, a path outside the
// socket directory, or an image that is not a bounded JPEG is an error.
// The package does not hide the operating system's capture indicator and
// does not accept a caller-supplied command line.
package display

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
)

const (
	// MaxJPEG is the largest frame that may cross the command channel.
	MaxJPEG = 384 * 1024
	// MaxRecordSeconds is the longest signed recording.
	MaxRecordSeconds = 60
	maxEdge          = 4096
	maxPixels        = 8_000_000
)

// ErrNotEnvelope means the command output is some other action result.
var ErrNotEnvelope = fmt.Errorf("not a display frame")

type envelope struct {
	Kind        string `json:"kind"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
	Image       string `json:"image"`
}

// Envelope wraps a validated JPEG for the signed command result.
func Envelope(frame []byte) ([]byte, error) {
	if err := ValidateJPEG(frame); err != nil {
		return nil, err
	}
	if len(frame) > MaxJPEG {
		return nil, fmt.Errorf("display frame exceeds limit")
	}
	sum := sha256.Sum256(frame)
	body, err := json.Marshal(envelope{
		Kind:        "display_frame",
		SHA256:      hex.EncodeToString(sum[:]),
		ContentType: "image/jpeg",
		Image:       base64.StdEncoding.EncodeToString(frame),
	})
	if err != nil {
		return nil, fmt.Errorf("encode display frame: %w", err)
	}
	return body, nil
}

// OpenEnvelope checks kind, hash, dimensions, and that the JPEG decodes.
func OpenEnvelope(raw []byte) ([]byte, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, ErrNotEnvelope
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var env envelope
	if err := dec.Decode(&env); err != nil || dec.More() || env.Kind != "display_frame" || env.ContentType != "image/jpeg" {
		return nil, ErrNotEnvelope
	}
	want, err := hex.DecodeString(env.SHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("display frame hash is invalid")
	}
	frame, err := base64.StdEncoding.DecodeString(env.Image)
	if err != nil {
		return nil, fmt.Errorf("display frame encoding is invalid")
	}
	sum := sha256.Sum256(frame)
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return nil, fmt.Errorf("display frame hash does not match")
	}
	if len(frame) > MaxJPEG {
		return nil, fmt.Errorf("display frame exceeds limit")
	}
	if err := ValidateJPEG(frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// ValidateJPEG rejects a truncated image, a non-JPEG, and a decompression bomb.
func ValidateJPEG(frame []byte) error {
	if len(frame) < 4 || frame[0] != 0xff || frame[1] != 0xd8 || frame[2] != 0xff {
		return fmt.Errorf("display frame is not a jpeg")
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(frame))
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxEdge || cfg.Height > maxEdge || cfg.Width*cfg.Height > maxPixels {
		return fmt.Errorf("display frame dimensions are not acceptable")
	}
	if _, err = jpeg.Decode(bytes.NewReader(frame)); err != nil {
		return fmt.Errorf("display frame is not a complete jpeg")
	}
	return nil
}

// FitJPEG keeps a valid frame that already fits and downscales one that does not.
func FitJPEG(frame []byte) ([]byte, error) {
	if err := ValidateJPEG(frame); err != nil {
		return nil, err
	}
	if len(frame) <= MaxJPEG {
		return frame, nil
	}
	img, err := jpeg.Decode(bytes.NewReader(frame))
	if err != nil {
		return nil, fmt.Errorf("display frame is not a complete jpeg")
	}
	fitted := scale(img, 1280, 720)
	for _, quality := range []int{70, 50, 30} {
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, fitted, &jpeg.Options{Quality: quality}); err != nil {
			return nil, fmt.Errorf("encode display frame: %w", err)
		}
		if buf.Len() <= MaxJPEG {
			return buf.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("display frame exceeds limit")
}

func scale(src image.Image, maxW, maxH int) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 1 || h < 1 {
		return image.NewRGBA(image.Rect(0, 0, 1, 1))
	}
	nw, nh := w, h
	if nw > maxW {
		nh = nh * maxW / nw
		nw = maxW
	}
	if nh > maxH {
		nw = nw * maxH / nh
		nh = maxH
	}
	if nw < 1 {
		nw = 1
	}
	if nh < 1 {
		nh = 1
	}
	if nw == w && nh == h {
		return src
	}
	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		sy := b.Min.Y + y*h/nh
		for x := 0; x < nw; x++ {
			sx := b.Min.X + x*w/nw
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}
