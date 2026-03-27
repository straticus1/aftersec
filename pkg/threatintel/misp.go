package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// MISPConfig represents the connection details for a MISP instance
type MISPConfig struct {
	BaseURL string `json:"base_url"`
	AuthKey string `json:"auth_key"`
	Enabled bool   `json:"enabled"`
}

// MISPClient is the core client for interacting with the Malware Information Sharing Platform
type MISPClient struct {
	config     *MISPConfig
	httpClient *http.Client
}

// MISPAttribute represents a single IOC/indicator exported from MISP
type MISPAttribute struct {
	ID        string `json:"id"`
	EventID   string `json:"event_id"`
	Type      string `json:"type"`
	Category  string `json:"category"`
	Value     string `json:"value"`
	ToIDS     bool   `json:"to_ids"`
	Timestamp string `json:"timestamp"`
}

type mispSearchResponse struct {
	Response struct {
		Attribute []MISPAttribute `json:"Attribute"`
	} `json:"response"`
}

// NewMISPClient initializes a new MISP connection wrapper
func NewMISPClient(cfg *MISPConfig) *MISPClient {
	return &MISPClient{
		config:     cfg,
		httpClient: &http.Client{},
	}
}

// Ping verifies connectivity and authentication with the MISP server
func (c *MISPClient) Ping(ctx context.Context) error {
	u, err := url.Parse(c.config.BaseURL)
	if err != nil {
		return err
	}
	u.Path = "/servers/getVersion.json"

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.config.AuthKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("MISP returned status %d", resp.StatusCode)
	}
	return nil
}

// SearchAttributes fetches actionable IDS network/file IOCs from MISP
func (c *MISPClient) SearchAttributes(ctx context.Context, attrType string) ([]MISPAttribute, error) {
	u, err := url.Parse(c.config.BaseURL)
	if err != nil {
		return nil, err
	}
	u.Path = "/attributes/restSearch"

	payload := map[string]interface{}{
		"returnFormat": "json",
		"to_ids":       true, // Only fetch attributes explicitly marked for IDS
	}
	
	if attrType != "" {
		payload["type"] = attrType
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.config.AuthKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MISP search failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var searchResp mispSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to decode MISP response: %w", err)
	}

	return searchResp.Response.Attribute, nil
}
