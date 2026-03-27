package clamav

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// DefinitionMetadata tracks ClamAV definition versions and status
type DefinitionMetadata struct {
	Version          string    `json:"version"`
	MainVersion      string    `json:"main_version"`
	DailyVersion     string    `json:"daily_version"`
	BytecodeVersion  string    `json:"bytecode_version"`
	UpdatedAt        time.Time `json:"updated_at"`
	TotalSizeBytes   int64     `json:"total_size_bytes"`
	TotalSizeMB      float64   `json:"total_size_mb"`
	DefinitionCount  int       `json:"definition_count"`
	FreshclamVersion string    `json:"freshclam_version"`
}

// Updater manages automatic ClamAV definition updates
type Updater struct {
	storagePath    string
	updateInterval time.Duration
	freshclamPath  string
	logger         *log.Logger
	stopChan       chan struct{}
}

// NewUpdater creates a new ClamAV definition updater
func NewUpdater(storagePath string, updateInterval time.Duration) (*Updater, error) {
	if storagePath == "" {
		storagePath = "/var/aftersec/clamav-defs"
	}

	if updateInterval == 0 {
		updateInterval = 4 * time.Hour
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Find freshclam binary
	freshclamPath, err := findFreshclam()
	if err != nil {
		return nil, fmt.Errorf("freshclam not found: %w", err)
	}

	return &Updater{
		storagePath:    storagePath,
		updateInterval: updateInterval,
		freshclamPath:  freshclamPath,
		logger:         log.New(os.Stdout, "[ClamAV Updater] ", log.LstdFlags),
		stopChan:       make(chan struct{}),
	}, nil
}

// Start begins the automatic update loop
func (u *Updater) Start(ctx context.Context) error {
	u.logger.Printf("Starting ClamAV definition updater (interval: %s)", u.updateInterval)
	u.logger.Printf("Storage path: %s", u.storagePath)
	u.logger.Printf("Freshclam path: %s", u.freshclamPath)

	// Run initial update
	if err := u.runUpdate(ctx); err != nil {
		u.logger.Printf("Initial update failed (will retry): %v", err)
	}

	// Start update loop
	ticker := time.NewTicker(u.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			u.logger.Println("Updater stopped (context cancelled)")
			return ctx.Err()
		case <-u.stopChan:
			u.logger.Println("Updater stopped (stop signal received)")
			return nil
		case <-ticker.C:
			if err := u.runUpdate(ctx); err != nil {
				u.logger.Printf("Update failed: %v", err)
			}
		}
	}
}

// Stop stops the updater
func (u *Updater) Stop() {
	close(u.stopChan)
}

// runUpdate executes a single update cycle
func (u *Updater) runUpdate(ctx context.Context) error {
	u.logger.Println("Running ClamAV definition update...")
	start := time.Now()

	// Run freshclam with custom database directory
	cmd := exec.CommandContext(ctx, u.freshclamPath,
		"--datadir="+u.storagePath,
		"--no-dns",
		"--verbose",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's just "already up to date"
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 1 {
			u.logger.Println("Definitions already up to date")
		} else {
			return fmt.Errorf("freshclam failed: %w (output: %s)", err, string(output))
		}
	}

	duration := time.Since(start)
	u.logger.Printf("Update completed in %s", duration)

	// Update metadata
	if err := u.updateMetadata(); err != nil {
		u.logger.Printf("Failed to update metadata: %v", err)
	}

	return nil
}

// updateMetadata reads definition files and updates metadata.json
func (u *Updater) updateMetadata() error {
	metadata := &DefinitionMetadata{
		UpdatedAt: time.Now(),
	}

	// Get freshclam version
	cmd := exec.Command(u.freshclamPath, "--version")
	if output, err := cmd.Output(); err == nil {
		metadata.FreshclamVersion = string(output)
	}

	// Calculate total size and count files
	defFiles := []string{"main.cvd", "main.cld", "daily.cvd", "daily.cld", "bytecode.cvd", "bytecode.cld"}
	var totalSize int64
	var count int

	for _, filename := range defFiles {
		path := filepath.Join(u.storagePath, filename)
		if info, err := os.Stat(path); err == nil {
			totalSize += info.Size()
			count++

			// Extract version from filename
			switch {
			case filename == "main.cvd" || filename == "main.cld":
				metadata.MainVersion = fmt.Sprintf("%d", info.ModTime().Unix())
			case filename == "daily.cvd" || filename == "daily.cld":
				metadata.DailyVersion = fmt.Sprintf("%d", info.ModTime().Unix())
			case filename == "bytecode.cvd" || filename == "bytecode.cld":
				metadata.BytecodeVersion = fmt.Sprintf("%d", info.ModTime().Unix())
			}
		}
	}

	metadata.TotalSizeBytes = totalSize
	metadata.TotalSizeMB = float64(totalSize) / (1024 * 1024)
	metadata.DefinitionCount = count
	metadata.Version = fmt.Sprintf("%d", time.Now().Unix())

	// Write metadata to JSON file
	metadataPath := filepath.Join(u.storagePath, "metadata.json")
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	u.logger.Printf("Metadata updated: %d definitions, %.1f MB total", count, metadata.TotalSizeMB)
	return nil
}

// GetMetadata returns the current definition metadata
func (u *Updater) GetMetadata() (*DefinitionMetadata, error) {
	metadataPath := filepath.Join(u.storagePath, "metadata.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty metadata if file doesn't exist yet
			return &DefinitionMetadata{
				UpdatedAt: time.Time{},
			}, nil
		}
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata DefinitionMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}

// ForceUpdate triggers an immediate update
func (u *Updater) ForceUpdate(ctx context.Context) error {
	u.logger.Println("Force update requested")
	return u.runUpdate(ctx)
}

// findFreshclam locates the freshclam binary
func findFreshclam() (string, error) {
	paths := []string{
		"/usr/bin/freshclam",
		"/usr/local/bin/freshclam",
		"/opt/homebrew/bin/freshclam",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Try PATH
	if path, err := exec.LookPath("freshclam"); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("freshclam binary not found in common locations")
}
