package darkscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// QuarantineMetadata stores information about an isolated file
type QuarantineMetadata struct {
	OriginalPath  string    `json:"original_path"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	Threats       []Threat  `json:"threats"`
}

// QuarantineFile isolates a malicious file to prevent execution
func QuarantineFile(ctx context.Context, source string, destDir string, threats []Threat) (string, error) {
	if destDir == "" {
		home, _ := os.UserHomeDir()
		destDir = filepath.Join(home, ".aftersec", "quarantine")
	}

	if err := os.MkdirAll(destDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	fileName := fmt.Sprintf("%s.%d.quarantine", filepath.Base(source), time.Now().Unix())
	destPath := filepath.Join(destDir, fileName)

	// Try atomic rename first
	if err := os.Rename(source, destPath); err != nil {
		// Fallback to copy and delete if across filesystem boundaries
		if err := copyFile(source, destPath); err != nil {
			return "", fmt.Errorf("failed to move file to quarantine: %w", err)
		}
		os.Remove(source)
	}

	// Remove execute permissions, making it read/write only for the owner
	os.Chmod(destPath, 0600)

	// Write metadata file
	meta := QuarantineMetadata{
		OriginalPath:  source,
		QuarantinedAt: time.Now(),
		Threats:       threats,
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	os.WriteFile(destPath+".meta.json", metaData, 0600)

	return destPath, nil
}

// copyFile is a helper to stream copy between filesystems
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
