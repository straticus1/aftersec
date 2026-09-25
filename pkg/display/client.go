package display

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"time"
)

// Client asks the user-session display process for one frame or a recording.
type Client struct {
	Path string
}

func NewClient(path string) *Client {
	return &Client{Path: path}
}

// Capture returns a fitted JPEG. seconds 0 is one frame. A positive value
// records for that many seconds, from 1 through 60.
func (c *Client) Capture(ctx context.Context, seconds int) ([]byte, error) {
	op := "shot"
	budget := 8 * time.Second
	if seconds != 0 {
		if _, _, err := FramePlan(seconds); err != nil {
			return nil, err
		}
		op = "record"
		budget = time.Duration(seconds+15) * time.Second
	}
	_, body, err := c.transact(ctx, request{Op: op, Seconds: seconds}, budget)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("display capture failed")
	}
	return body, nil
}

func (c *Client) Arm(ctx context.Context) error {
	_, _, err := c.transact(ctx, request{Op: "arm"}, 5*time.Second)
	return err
}

func (c *Client) Disarm(ctx context.Context) error {
	_, _, err := c.transact(ctx, request{Op: "disarm"}, 5*time.Second)
	return err
}

func (c *Client) NextStolen(ctx context.Context) (string, []byte, error) {
	resp, body, err := c.transact(ctx, request{Op: "stolen_next"}, 8*time.Second)
	if err != nil || len(body) == 0 {
		return "", nil, err
	}
	return resp.ID, body, nil
}

func (c *Client) AckStolen(ctx context.Context, id string) error {
	_, _, err := c.transact(ctx, request{Op: "stolen_ack", ID: id}, 5*time.Second)
	return err
}

func (c *Client) transact(ctx context.Context, req request, budget time.Duration) (responseHeader, []byte, error) {
	if c == nil || !filepath.IsAbs(c.Path) {
		return responseHeader{}, nil, fmt.Errorf("display agent is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return responseHeader{}, nil, fmt.Errorf("display agent is not available")
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > budget {
		deadline = time.Now().Add(budget)
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return responseHeader{}, nil, fmt.Errorf("display agent is not available")
	}
	header, err := json.Marshal(req)
	if err != nil {
		return responseHeader{}, nil, err
	}
	if err = writeMsg(conn, header, nil); err != nil {
		return responseHeader{}, nil, fmt.Errorf("display agent is not available")
	}
	rawHeader, body, err := readMsg(conn, MaxJPEG)
	if err != nil {
		return responseHeader{}, nil, fmt.Errorf("display agent is not available")
	}
	var resp responseHeader
	if json.Unmarshal(rawHeader, &resp) != nil || !resp.OK {
		if resp.Error != "" && len(resp.Error) <= 200 {
			return responseHeader{}, nil, fmt.Errorf("%s", resp.Error)
		}
		return responseHeader{}, nil, fmt.Errorf("display capture failed")
	}
	if len(body) == 0 {
		return resp, nil, nil
	}
	if resp.ContentType != "image/jpeg" || len(body) != resp.Bytes || len(body) > MaxJPEG {
		return responseHeader{}, nil, fmt.Errorf("display capture failed")
	}
	want, err := hex.DecodeString(resp.SHA256)
	if err != nil || len(want) != sha256.Size {
		return responseHeader{}, nil, fmt.Errorf("display capture failed")
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return responseHeader{}, nil, fmt.Errorf("display capture failed")
	}
	if err = ValidateJPEG(body); err != nil {
		return responseHeader{}, nil, err
	}
	return resp, body, nil
}
