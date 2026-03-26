package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	FileHashesBaseURL = "https://api.filehashes.io/v1"
	FileHashesTimeout = 10 * time.Second
)

// FileHashesClient handles interactions with FileHashes.io global hash repository
type FileHashesClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// HashRecord represents a file hash entry with threat intelligence
type HashRecord struct {
	Hash            string    `json:"hash"`
	Algorithm       string    `json:"algorithm"` // sha256, sha1, md5
	ThreatLevel     int       `json:"threat_level"` // 0-10 (0=safe, 10=critical)
	SignedStatus    bool      `json:"signed_status"`
	SeenTimes       int       `json:"seen_times"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	SubmittedBy     string    `json:"submitted_by,omitempty"`
	IsMalicious     bool      `json:"is_malicious"`
	ThreatFamily    string    `json:"threat_family,omitempty"`
	DetectionNames  []string  `json:"detection_names,omitempty"`
}

// HashSubmission represents metadata submitted with a new hash
type HashSubmission struct {
	Hash              string    `json:"hash"`
	Algorithm         string    `json:"algorithm"`
	ThreatLevel       int       `json:"threat_level"`
	SignedStatus      bool      `json:"signed_status"`
	SubmittedCountry  string    `json:"submitted_country,omitempty"`
	SubmittedState    string    `json:"submitted_state,omitempty"`
	SubmittedISP      string    `json:"submitted_isp,omitempty"`
	FileSize          int64     `json:"file_size,omitempty"`
	FileName          string    `json:"file_name,omitempty"`
	DetectedBy        string    `json:"detected_by"` // "aftersec", "yara", "clamav", etc.
	Timestamp         time.Time `json:"timestamp"`
}

// GeoLocation holds geographic location data for hash submissions
type GeoLocation struct {
	Country string
	State   string
	City    string
	ISP     string
	IP      string
}

// NewFileHashesClient creates a new FileHashes.io API client
func NewFileHashesClient(apiKey string) *FileHashesClient {
	return &FileHashesClient{
		apiKey:  apiKey,
		baseURL: FileHashesBaseURL,
		httpClient: &http.Client{
			Timeout: FileHashesTimeout,
		},
	}
}

// LookupHash queries the global hash database for threat intelligence
func (c *FileHashesClient) LookupHash(ctx context.Context, hash string) (*HashRecord, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash cannot be empty")
	}

	url := fmt.Sprintf("%s/hashes/%s", c.baseURL, hash)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "AfterSec/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Hash not in database yet - this is normal for new files
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var record HashRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &record, nil
}

// SubmitHash submits a new hash with metadata to the global repository
func (c *FileHashesClient) SubmitHash(ctx context.Context, submission *HashSubmission) error {
	if submission.Hash == "" {
		return fmt.Errorf("hash cannot be empty")
	}

	// Default to sha256 if not specified
	if submission.Algorithm == "" {
		submission.Algorithm = "sha256"
	}

	// Set timestamp if not provided
	if submission.Timestamp.IsZero() {
		submission.Timestamp = time.Now()
	}

	body, err := json.Marshal(submission)
	if err != nil {
		return fmt.Errorf("failed to marshal submission: %w", err)
	}

	url := fmt.Sprintf("%s/hashes", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AfterSec/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetGeoLocation retrieves geographic information for the current system
// This uses ipinfo.io for geolocation (free tier: 50k requests/month)
func GetGeoLocation(ctx context.Context) (*GeoLocation, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %d", resp.StatusCode)
	}

	var result struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Org      string `json:"org"` // ISP info
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &GeoLocation{
		Country: result.Country,
		State:   result.Region,
		City:    result.City,
		ISP:     result.Org,
		IP:      result.IP,
	}, nil
}

// GetGeoLocationFallback tries to get geo info without external API (less accurate)
func GetGeoLocationFallback() *GeoLocation {
	// Get outbound IP by dialing a public DNS server
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return &GeoLocation{
			Country: "Unknown",
			State:   "Unknown",
			ISP:     "Unknown",
		}
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return &GeoLocation{
		Country: "Unknown",
		State:   "Unknown",
		ISP:     "Unknown",
		IP:      localAddr.IP.String(),
	}
}

// BatchLookup queries multiple hashes in a single request (more efficient)
func (c *FileHashesClient) BatchLookup(ctx context.Context, hashes []string) (map[string]*HashRecord, error) {
	if len(hashes) == 0 {
		return make(map[string]*HashRecord), nil
	}

	if len(hashes) > 100 {
		return nil, fmt.Errorf("batch size cannot exceed 100 hashes")
	}

	body, err := json.Marshal(map[string][]string{"hashes": hashes})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/hashes/batch", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AfterSec/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]*HashRecord
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}
