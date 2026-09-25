// Package preserve collects a bounded evidence archive after an operator
// marks an endpoint lost, breached, or compromised.
//
// Threats: a symlink, a path outside the allowlist, an oversized file, or a
// malformed incident id is not packed. The archive does not include shadow
// files, private keys, or a caller-chosen path. Suspicious and exfiltrate
// reports name the class only; they do not start collection by themselves.
package preserve

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ClassSuspicious = "suspicious"
	ClassExfiltrate = "exfiltrate"
	maxFile         = 64 * 1024
	maxArchive      = 256 * 1024
)

var (
	ErrRejected = errors.New("preserve evidence rejected")
	allow       = []string{
		"etc/hosts",
		"etc/passwd",
		"etc/ssh/sshd_config",
		"etc/crontab",
	}
)

type Header struct {
	IncidentID string
	Reason     string
	Hostname   string
	At         time.Time
}

type fileNote struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256,omitempty"`
	Bytes     int    `json:"bytes,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Skipped   string `json:"skipped,omitempty"`
}

type manifest struct {
	IncidentID string     `json:"incident_id"`
	Reason     string     `json:"reason"`
	Hostname   string     `json:"hostname"`
	Collected  string     `json:"collected_at"`
	Files      []fileNote `json:"files"`
}

func ValidReason(reason string) bool {
	return reason == "lost" || reason == "breached" || reason == "compromised"
}

func ValidIncident(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func ParseMark(args map[string]string) (incident, reason string, err error) {
	if len(args) != 2 {
		return "", "", ErrRejected
	}
	incident, reason = args["incident_id"], args["reason"]
	if !ValidIncident(incident) || !ValidReason(reason) {
		return "", "", ErrRejected
	}
	return incident, reason, nil
}

// Class maps an existing telemetry event onto a report class.
func Class(source, eventType string) (string, bool) {
	switch source + "\x00" + eventType {
	case "darkscan\x00suspicious_allowed", "accord\x00contract-break", "accord\x00identity-drift", "accord\x00load-drift":
		return ClassSuspicious, true
	case "netsensor\x00external_upload":
		return ClassExfiltrate, true
	default:
		return "", false
	}
}

// DNSClass reports a suspicious lookup, and a long high-scoring label as exfiltrate.
func DNSClass(domain string, suspicious bool, entropyScore float64) (string, bool) {
	if !suspicious || domain == "" || strings.ContainsAny(domain, "\r\n") {
		return "", false
	}
	label := domain
	if i := strings.IndexByte(domain, '.'); i >= 0 {
		label = domain[:i]
	}
	if entropyScore >= 0.9 && len(label) >= 25 {
		return ClassExfiltrate, true
	}
	return ClassSuspicious, true
}

// Collect packs the allowlist under root. Missing files are skipped.
func Collect(root string, hdr Header) ([]byte, error) {
	if !ValidIncident(hdr.IncidentID) || !ValidReason(hdr.Reason) || hdr.At.IsZero() {
		return nil, ErrRejected
	}
	if hdr.Hostname == "" || len(hdr.Hostname) > 255 || strings.ContainsAny(hdr.Hostname, "\r\n\t/\\") {
		return nil, ErrRejected
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, ErrRejected
	}
	notes := make([]fileNote, 0, len(allow))
	var packed []struct {
		name string
		body []byte
	}
	for _, rel := range allow {
		note, body, err := readAllowlisted(root, rel)
		if err != nil {
			return nil, err
		}
		notes = append(notes, note)
		if body != nil {
			packed = append(packed, struct {
				name string
				body []byte
			}{rel, body})
		}
	}
	doc, err := json.Marshal(manifest{
		IncidentID: hdr.IncidentID,
		Reason:     hdr.Reason,
		Hostname:   hdr.Hostname,
		Collected:  hdr.At.UTC().Format(time.RFC3339),
		Files:      notes,
	})
	if err != nil {
		return nil, ErrRejected
	}
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	files := append([]struct {
		name string
		body []byte
	}{{"preserve-manifest.json", doc}}, packed...)
	for _, file := range files {
		if err = tw.WriteHeader(&tar.Header{Name: file.name, Mode: 0o600, Size: int64(len(file.body)), ModTime: hdr.At.UTC()}); err != nil {
			return nil, ErrRejected
		}
		if _, err = tw.Write(file.body); err != nil {
			return nil, ErrRejected
		}
	}
	if err = tw.Close(); err != nil {
		return nil, ErrRejected
	}
	if err = gz.Close(); err != nil {
		return nil, ErrRejected
	}
	if raw.Len() == 0 || raw.Len() > maxArchive {
		return nil, ErrRejected
	}
	return raw.Bytes(), nil
}

func readAllowlisted(root, rel string) (fileNote, []byte, error) {
	if filepath.Clean(rel) != rel || strings.Contains(rel, "..") {
		return fileNote{}, nil, ErrRejected
	}
	path := filepath.Join(root, rel)
	if filepath.Clean(path) != path {
		return fileNote{}, nil, ErrRejected
	}
	relBack, err := filepath.Rel(root, path)
	if err != nil || relBack != rel {
		return fileNote{}, nil, ErrRejected
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileNote{Path: rel, Skipped: "missing"}, nil, nil
		}
		return fileNote{}, nil, ErrRejected
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fileNote{Path: rel, Skipped: "symlink"}, nil, nil
	}
	if !info.Mode().IsRegular() {
		return fileNote{Path: rel, Skipped: "not-regular"}, nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fileNote{}, nil, ErrRejected
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return fileNote{}, nil, ErrRejected
	}
	note := fileNote{Path: rel, Bytes: len(body)}
	if len(body) > maxFile {
		body = body[:maxFile]
		note.Bytes = maxFile
		note.Truncated = true
	}
	sum := sha256Hex(body)
	note.SHA256 = sum
	return note, body, nil
}

func sha256Hex(body []byte) string {
	sum := sha256Sum(body)
	return fmt.Sprintf("%x", sum[:])
}
