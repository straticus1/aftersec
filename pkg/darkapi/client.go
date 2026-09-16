// Package darkapi reports Aftersec evidence using a shared DarkAPI host identity.
package darkapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Credentials struct {
	BaseURL  string `json:"base_url"`
	DeviceID string `json:"device_id"`
	APIKey   string `json:"api_key"`
	App      string `json:"app"`
}
type Client struct {
	credentials Credentials
	http        *http.Client
}
type Event struct {
	EventID string   `json:"event_id"`
	Event   Evidence `json:"event"`
}
type Evidence struct {
	SchemaVersion    int            `json:"schema_version,omitempty"`
	BootID           string         `json:"boot_id,omitempty"`
	StreamID         string         `json:"stream_id,omitempty"`
	Sequence         int64          `json:"sequence,omitempty"`
	AgentVersion     string         `json:"agent_version,omitempty"`
	CollectionStatus string         `json:"collection_status,omitempty"`
	Facts            map[string]any `json:"facts,omitempty"`
	Type             string         `json:"type"`
	Category         string         `json:"category,omitempty"`
	Source           string         `json:"source"`
	Severity         string         `json:"severity"`
	Time             string         `json:"time"`
	Data             map[string]any `json:"data"`
	CorrelationID    string         `json:"correlation_id,omitempty"`
	Entities         map[string]any `json:"entities,omitempty"`
}

func NormalizeURL(raw string) (string, error) {
	if raw == "" {
		raw = "https://api.darkapi.io"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("DarkAPI requires an HTTPS base URL without credentials, query or fragment")
	}
	if strings.EqualFold(u.Host, "darkapi.io") && strings.TrimRight(u.Path, "/") == "/api" {
		return "https://api.darkapi.io", nil
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("use the API hostname without a path")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
func New(credentials Credentials) (*Client, error) {
	base, err := NormalizeURL(credentials.BaseURL)
	if err != nil {
		return nil, err
	}
	credentials.BaseURL = base
	return &Client{credentials: credentials, http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func Load(path string) (*Client, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 16384 || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, fmt.Errorf("credential file must be a private regular file")
	}
	if err := checkCredentialPermissions(path, info); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var saved Credentials
	if json.Unmarshal(b, &saved) != nil || saved.DeviceID == "" || saved.APIKey == "" || saved.App != "aftersec" {
		return nil, fmt.Errorf("invalid Aftersec device credentials")
	}
	return New(saved)
}
func DefaultCredentialPath() string {
	root, err := os.UserConfigDir()
	if err != nil {
		root = "."
	}
	return filepath.Join(root, "aftersec", "darkapi.json")
}
func (c *Client) DeviceID() string { return c.credentials.DeviceID }
func (c *Client) request(ctx context.Context, method, path string, body, out any, auth bool) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("request exceeds 1 MiB")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.credentials.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aftersec-darkapi/1")
	if auth {
		if c.credentials.APIKey == "" || c.credentials.DeviceID == "" {
			return fmt.Errorf("enroll Aftersec first")
		}
		req.Header.Set("X-API-Key", c.credentials.APIKey)
		req.Header.Set("X-Device-ID", c.credentials.DeviceID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("DarkAPI connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil || len(b) > 4<<20 {
		return fmt.Errorf("invalid DarkAPI response size")
	}
	if out != nil {
		if json.Unmarshal(b, out) != nil {
			return fmt.Errorf("invalid DarkAPI JSON response")
		}
	}
	return nil
}
func (c *Client) Enroll(ctx context.Context, token, path, version string) error {
	if token == "" {
		return fmt.Errorf("set AFTERSEC_DARKAPI_ENROLLMENT_TOKEN")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("credential file exists; do not overwrite an enrolled identity")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	var result struct {
		Success  bool   `json:"success"`
		DeviceID string `json:"device_id"`
		APIKey   string `json:"api_key"`
		App      string `json:"app"`
	}
	if err := c.request(ctx, "POST", "/api/v1/aftersec/enroll", map[string]string{"enrollment_token": token, "hostname": hostname, "platform": runtime.GOOS, "architecture": runtime.GOARCH, "agent_version": version}, &result, false); err != nil {
		return err
	}
	if !result.Success || !strings.HasPrefix(result.DeviceID, "dev_") || result.APIKey == "" || result.App != "aftersec" {
		return fmt.Errorf("invalid enrollment response")
	}
	saved := Credentials{BaseURL: c.credentials.BaseURL, DeviceID: result.DeviceID, APIKey: result.APIKey, App: result.App}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, _ := json.Marshal(saved)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("enrolled but could not save credentials: %w", err)
	}
	if err = secureCredentialFile(path); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	c.credentials = saved
	return nil
}
func (c *Client) Heartbeat(ctx context.Context) error {
	var result struct {
		Success  bool   `json:"success"`
		DeviceID string `json:"device_id"`
	}
	if err := c.request(ctx, "POST", "/api/v1/aftersec/heartbeat", map[string]any{"capabilities": map[string]string{"telemetry": "active", "agent_resources": "active"}}, &result, true); err != nil {
		return err
	}
	if !result.Success || result.DeviceID != c.DeviceID() {
		return fmt.Errorf("invalid heartbeat acknowledgment")
	}
	return nil
}
func (c *Client) Config(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := c.request(ctx, "GET", "/api/v1/aftersec/config", nil, &result, true)
	if err == nil && (result["device_id"] != c.DeviceID() || result["app"] != "aftersec") {
		return nil, fmt.Errorf("configuration identity mismatch")
	}
	return result, err
}
func (c *Client) Send(ctx context.Context, events []Event) error {
	if len(events) == 0 || len(events) > 100 {
		return fmt.Errorf("batch must contain 1 to 100 events")
	}
	var result struct {
		Success  bool     `json:"success"`
		DeviceID string   `json:"device_id"`
		IDs      []string `json:"accepted_event_ids"`
	}
	err := c.request(ctx, "POST", "/api/v1/aftersec/telemetry", map[string]any{"device_id": c.DeviceID(), "events": events}, &result, true)
	if err != nil {
		return err
	}
	if !result.Success || result.DeviceID != c.DeviceID() || len(result.IDs) != len(events) {
		return fmt.Errorf("invalid telemetry acknowledgment")
	}
	for i, id := range result.IDs {
		if id != events[i].EventID {
			return fmt.Errorf("telemetry acknowledgment does not match submitted event IDs")
		}
	}
	return nil
}
