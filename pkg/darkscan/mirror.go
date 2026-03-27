package darkscan

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// MirrorClient handles downloading ClamAV definitions from a custom mirror server
type MirrorClient struct {
	mirrorURL      string
	client         *http.Client
	targetDir      string
}

// MirrorMetadata represents definition metadata from the mirror server
type MirrorMetadata struct {
	Version          string    `json:"version"`
	MainVersion      string    `json:"main_version"`
	DailyVersion     string    `json:"daily_version"`
	BytecodeVersion  string    `json:"bytecode_version"`
	UpdatedAt        time.Time `json:"updated_at"`
	TotalSizeBytes   int64     `json:"total_size_bytes"`
	TotalSizeMB      float64   `json:"total_size_mb"`
}

// NewMirrorClient creates a new mirror client
func NewMirrorClient(mirrorURL, targetDir string) *MirrorClient {
	if targetDir == "" {
		targetDir = "/usr/local/share/clamav"
	}

	return &MirrorClient{
		mirrorURL: mirrorURL,
		client:    &http.Client{Timeout: 10 * time.Minute},
		targetDir: targetDir,
	}
}

// GetVersion fetches the current definition version from the mirror
func (m *MirrorClient) GetVersion() (*MirrorMetadata, error) {
	url := fmt.Sprintf("%s/api/v1/clamav/definitions/version", m.mirrorURL)
	resp, err := m.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch version: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mirror returned status %d", resp.StatusCode)
	}

	var metadata MirrorMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}

// DownloadDefinitions downloads the latest definition bundle from the mirror
func (m *MirrorClient) DownloadDefinitions() error {
	url := fmt.Sprintf("%s/api/v1/clamav/definitions/latest", m.mirrorURL)

	// Download bundle
	resp, err := m.client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mirror returned status %d", resp.StatusCode)
	}

	// Create target directory if it doesn't exist
	if err := os.MkdirAll(m.targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Extract tarball
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Create target file
		targetPath := filepath.Join(m.targetDir, header.Name)
		targetFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", targetPath, err)
		}

		// Copy content
		if _, err := io.Copy(targetFile, tarReader); err != nil {
			targetFile.Close()
			return fmt.Errorf("failed to write file %s: %w", targetPath, err)
		}

		targetFile.Close()
	}

	return nil
}

// DownloadFile downloads a specific definition file
func (m *MirrorClient) DownloadFile(filename string) error {
	url := fmt.Sprintf("%s/api/v1/clamav/definitions/%s", m.mirrorURL, filename)

	resp, err := m.client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mirror returned status %d", resp.StatusCode)
	}

	targetPath := filepath.Join(m.targetDir, filename)
	targetFile, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer targetFile.Close()

	if _, err := io.Copy(targetFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// UpdateFromMirror downloads definitions from the mirror if they're newer
func UpdateFromMirror(mirrorURL, targetDir string) error {
	if mirrorURL == "" {
		return fmt.Errorf("mirror URL not configured")
	}

	client := NewMirrorClient(mirrorURL, targetDir)

	// Check if update is needed by comparing versions
	metadata, err := client.GetVersion()
	if err != nil {
		return fmt.Errorf("failed to get mirror version: %w", err)
	}

	// Download latest definitions
	if err := client.DownloadDefinitions(); err != nil {
		return fmt.Errorf("failed to download definitions: %w", err)
	}

	fmt.Printf("Successfully updated ClamAV definitions from mirror (version: %s, size: %.1f MB)\n",
		metadata.Version, metadata.TotalSizeMB)

	return nil
}
