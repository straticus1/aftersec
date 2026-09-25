package display

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Agent is the user-session process. It accepts one request per connection
// and only from uid 0, which is the enrolled system daemon.
type Agent struct {
	Capturer Capturer
	Spool    string
	Peer     func(*net.UnixConn) (int, error)
	Stolen   *StolenHooks
	recordMu sync.Mutex
}

type request struct {
	Op      string `json:"op"`
	Seconds int    `json:"seconds,omitempty"`
	ID      string `json:"id,omitempty"`
}

type responseHeader struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Bytes       int    `json:"bytes,omitempty"`
	ID          string `json:"id,omitempty"`
}

// StolenHooks is the user-session camera used after a stolen mark.
type StolenHooks struct {
	Arm    func() error
	Disarm func() error
	Next   func() (string, []byte, error)
	Ack    func(string) error
}

// Serve listens on an absolute unix socket inside a private directory.
func (a *Agent) Serve(ctx context.Context, socketPath string) error {
	if a == nil || a.Capturer == nil {
		return fmt.Errorf("display agent is not configured")
	}
	dir, err := socketDir(socketPath)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create display socket directory: %w", err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("protect display socket directory: %w", err)
	}
	if a.Spool != "" {
		if err = os.MkdirAll(a.Spool, 0700); err != nil {
			return fmt.Errorf("create display spool: %w", err)
		}
		if err = os.Chmod(a.Spool, 0700); err != nil {
			return fmt.Errorf("protect display spool: %w", err)
		}
	}
	if info, statErr := os.Lstat(socketPath); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("display socket path exists and is not a socket")
		}
		if err = os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale display socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen display socket: %w", err)
	}
	if err = os.Chmod(socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("protect display socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept display connection: %w", err)
		}
		go a.handle(conn)
	}
}

func socketDir(socketPath string) (string, error) {
	if !filepath.IsAbs(socketPath) {
		return "", fmt.Errorf("display socket path must be absolute")
	}
	dir := filepath.Dir(filepath.Clean(socketPath))
	switch dir {
	case "/", "/tmp", "/var", "/usr", "/private", "/private/tmp", "/var/tmp", "/Users", "/home":
		return "", fmt.Errorf("display socket directory is too broad")
	}
	return dir, nil
}

func (a *Agent) handle(conn net.Conn) {
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	peer := a.Peer
	if peer == nil {
		peer = peerUID
	}
	uid, err := peer(unixConn)
	if err != nil || uid != 0 {
		return
	}
	_ = unixConn.SetDeadline(time.Now().Add(5 * time.Second))
	header, body, err := readMsg(unixConn, 1024)
	if err != nil || len(body) != 0 {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(header))
	dec.DisallowUnknownFields()
	var req request
	if dec.Decode(&req) != nil {
		return
	}
	budget := 8 * time.Second
	if req.Op == "record" {
		budget = time.Duration(req.Seconds+15) * time.Second
	}
	_ = unixConn.SetDeadline(time.Now().Add(budget))
	taken, err := a.dispatch(req)
	if errors.Is(err, errNoStolenPhoto) {
		a.reply(unixConn, responseHeader{OK: true}, nil)
		return
	}
	if err != nil {
		msg := err.Error()
		if len(msg) > 200 {
			msg = "display capture failed"
		}
		a.reply(unixConn, responseHeader{Error: msg}, nil)
		return
	}
	if len(taken.frame) == 0 {
		a.reply(unixConn, responseHeader{OK: true, ID: taken.id}, nil)
		return
	}
	sum := sha256.Sum256(taken.frame)
	a.reply(unixConn, responseHeader{
		OK: true, SHA256: hex.EncodeToString(sum[:]), ContentType: "image/jpeg", Bytes: len(taken.frame), ID: taken.id,
	}, taken.frame)
}

var errNoStolenPhoto = errors.New("no stolen photo")

type takenFrame struct {
	frame []byte
	id    string
}

func (a *Agent) dispatch(req request) (takenFrame, error) {
	switch req.Op {
	case "shot":
		if req.Seconds != 0 {
			return takenFrame{}, fmt.Errorf("display shot takes no arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		raw, err := a.Capturer.Frame(ctx)
		if err != nil {
			log.Printf("display capture failed: %v", err)
			return takenFrame{}, fmt.Errorf("display capture failed")
		}
		frame, err := FitJPEG(raw)
		if err != nil {
			return takenFrame{}, fmt.Errorf("display capture failed")
		}
		return takenFrame{frame: frame}, nil
	case "record":
		if !a.recordMu.TryLock() {
			return takenFrame{}, fmt.Errorf("display recording is already active")
		}
		defer a.recordMu.Unlock()
		if _, _, err := FramePlan(req.Seconds); err != nil {
			return takenFrame{}, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Seconds+12)*time.Second)
		defer cancel()
		frame, err := Record(ctx, a.Capturer, req.Seconds, a.Spool, nil)
		if err != nil {
			log.Printf("display recording failed: %v", err)
			return takenFrame{}, fmt.Errorf("display recording failed")
		}
		return takenFrame{frame: frame}, nil
	case "arm", "disarm", "stolen_next", "stolen_ack":
		return a.stolen(req)
	default:
		return takenFrame{}, fmt.Errorf("display operation is not supported")
	}
}

func (a *Agent) stolen(req request) (takenFrame, error) {
	if a.Stolen == nil || a.Stolen.Arm == nil || a.Stolen.Disarm == nil || a.Stolen.Next == nil || a.Stolen.Ack == nil {
		return takenFrame{}, fmt.Errorf("stolen camera is not configured")
	}
	switch req.Op {
	case "arm":
		if err := a.Stolen.Arm(); err != nil {
			return takenFrame{}, err
		}
		return takenFrame{}, nil
	case "disarm":
		if err := a.Stolen.Disarm(); err != nil {
			return takenFrame{}, err
		}
		return takenFrame{}, nil
	case "stolen_ack":
		if err := a.Stolen.Ack(req.ID); err != nil {
			return takenFrame{}, err
		}
		return takenFrame{}, nil
	case "stolen_next":
		id, frame, err := a.Stolen.Next()
		if err != nil {
			return takenFrame{}, err
		}
		if id == "" || len(frame) == 0 {
			return takenFrame{}, errNoStolenPhoto
		}
		return takenFrame{frame: frame, id: id}, nil
	default:
		return takenFrame{}, fmt.Errorf("display operation is not supported")
	}
}

func (a *Agent) reply(conn net.Conn, header responseHeader, body []byte) {
	raw, err := json.Marshal(header)
	if err != nil {
		return
	}
	if len(header.Error) > 200 {
		return
	}
	_ = writeMsg(conn, raw, body)
}

func writeMsg(w io.Writer, header, body []byte) error {
	if len(header) == 0 || len(header) > 4096 || len(body) > MaxJPEG {
		return fmt.Errorf("display message exceeds limit")
	}
	var lenb [4]byte
	binary.BigEndian.PutUint32(lenb[:], uint32(len(header)))
	if _, err := writeAll(w, lenb[:]); err != nil {
		return err
	}
	if _, err := writeAll(w, header); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(lenb[:], uint32(len(body)))
	if _, err := writeAll(w, lenb[:]); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := writeAll(w, body)
	return err
}

func readMsg(r io.Reader, maxBody int) ([]byte, []byte, error) {
	var lenb [4]byte
	if _, err := io.ReadFull(r, lenb[:]); err != nil {
		return nil, nil, err
	}
	n := binary.BigEndian.Uint32(lenb[:])
	if n == 0 || n > 4096 {
		return nil, nil, fmt.Errorf("display header length")
	}
	header := make([]byte, n)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, lenb[:]); err != nil {
		return nil, nil, err
	}
	n = binary.BigEndian.Uint32(lenb[:])
	if int(n) > maxBody || int(n) > MaxJPEG {
		return nil, nil, fmt.Errorf("display body length")
	}
	if n == 0 {
		return header, nil, nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	return header, body, nil
}

func writeAll(w io.Writer, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		wrote, err := w.Write(b[n:])
		n += wrote
		if err != nil {
			return n, err
		}
		if wrote == 0 {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}
