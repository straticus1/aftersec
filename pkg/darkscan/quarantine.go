package darkscan

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// QuarantineManager manages quarantined files
type QuarantineManager struct {
	config      *Config
	db          *sql.DB
	enabled     bool
	quarantineDir string
}

// Note: QuarantineInfo type is defined in interface.go

// NewQuarantineManager creates a new quarantine manager
func NewQuarantineManager(cfg *Config) (*QuarantineManager, error) {
	if !cfg.Quarantine.Enabled {
		return &QuarantineManager{enabled: false}, nil
	}

	quarantineDir := cfg.Quarantine.Path
	if quarantineDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		quarantineDir = filepath.Join(homeDir, ".aftersec", "quarantine")
	}

	// Expand tilde
	if len(quarantineDir) > 0 && quarantineDir[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		quarantineDir = filepath.Join(homeDir, quarantineDir[1:])
	}

	// Create quarantine directory
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	// Open metadata database
	dbPath := filepath.Join(quarantineDir, "quarantine.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open quarantine database: %w", err)
	}

	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS quarantine (
		id TEXT PRIMARY KEY,
		original_path TEXT,
		quarantine_path TEXT,
		quarantined_at TIMESTAMP,
		file_size INTEGER,
		file_hash TEXT,
		threats TEXT,
		encrypted BOOLEAN,
		restore_count INTEGER DEFAULT 0,
		last_accessed TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_quarantined_at ON quarantine(quarantined_at);
	CREATE INDEX IF NOT EXISTS idx_file_hash ON quarantine(file_hash);
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &QuarantineManager{
		config:        cfg,
		db:            db,
		enabled:       true,
		quarantineDir: quarantineDir,
	}, nil
}

// QuarantineFile isolates a malicious file to prevent execution
func (qm *QuarantineManager) QuarantineFile(ctx context.Context, source string, threats []Threat) (string, error) {
	if !qm.enabled {
		return "", fmt.Errorf("quarantine not enabled")
	}

	// Get file info
	info, err := os.Stat(source)
	if err != nil {
		return "", fmt.Errorf("failed to stat file: %w", err)
	}

	// Calculate file hash
	fileHash, err := calculateFileHash(source)
	if err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Generate quarantine ID
	quarantineID := fmt.Sprintf("%s_%d", fileHash[:16], time.Now().Unix())

	// Determine destination path
	fileName := fmt.Sprintf("%s.quarantine", quarantineID)
	destPath := filepath.Join(qm.quarantineDir, fileName)

	// Move/copy file
	if qm.config.Quarantine.Encrypt {
		// Encrypt and copy
		if err := qm.encryptFile(source, destPath); err != nil {
			return "", fmt.Errorf("failed to encrypt file: %w", err)
		}
		os.Remove(source)
	} else {
		// Try atomic rename first
		if err := os.Rename(source, destPath); err != nil {
			// Fallback to copy and delete if across filesystem boundaries
			if err := copyFile(source, destPath); err != nil {
				return "", fmt.Errorf("failed to move file to quarantine: %w", err)
			}
			os.Remove(source)
		}
	}

	// Remove execute permissions
	os.Chmod(destPath, 0600)

	// Marshal threats to JSON
	threatsJSON, err := json.Marshal(threats)
	if err != nil {
		threatsJSON = []byte("[]")
	}

	// Store metadata in database
	query := `
		INSERT INTO quarantine (id, original_path, quarantine_path, quarantined_at, file_size, file_hash, threats, encrypted, last_accessed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = qm.db.ExecContext(ctx, query,
		quarantineID,
		source,
		destPath,
		time.Now(),
		info.Size(),
		fileHash,
		string(threatsJSON),
		qm.config.Quarantine.Encrypt,
		time.Now(),
	)

	if err != nil {
		// Clean up file if database insert fails
		os.Remove(destPath)
		return "", fmt.Errorf("failed to store quarantine metadata: %w", err)
	}

	return quarantineID, nil
}

// ListQuarantine returns all quarantined files
func (qm *QuarantineManager) ListQuarantine(ctx context.Context) ([]*QuarantineInfo, error) {
	if !qm.enabled {
		return nil, fmt.Errorf("quarantine not enabled")
	}

	query := `
		SELECT id, original_path, quarantined_at, file_size, file_hash, threats, encrypted
		FROM quarantine
		ORDER BY quarantined_at DESC
	`

	rows, err := qm.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query quarantine: %w", err)
	}
	defer rows.Close()

	var results []*QuarantineInfo
	for rows.Next() {
		var info QuarantineInfo
		var threatsJSON string

		err := rows.Scan(
			&info.QuarantineID,
			&info.OriginalPath,
			&info.QuarantinedAt,
			&info.FileSize,
			&info.FileHash,
			&threatsJSON,
			&info.Encrypted,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Parse threats JSON
		if threatsJSON != "" {
			if err := json.Unmarshal([]byte(threatsJSON), &info.Threats); err != nil {
				info.Threats = []Threat{}
			}
		}

		results = append(results, &info)
	}

	return results, nil
}

// GetQuarantineInfo retrieves information about a quarantined file
func (qm *QuarantineManager) GetQuarantineInfo(ctx context.Context, quarantineID string) (*QuarantineInfo, error) {
	if !qm.enabled {
		return nil, fmt.Errorf("quarantine not enabled")
	}

	query := `
		SELECT id, original_path, quarantined_at, file_size, file_hash, threats, encrypted
		FROM quarantine
		WHERE id = ?
	`

	var info QuarantineInfo
	var threatsJSON string

	err := qm.db.QueryRowContext(ctx, query, quarantineID).Scan(
		&info.QuarantineID,
		&info.OriginalPath,
		&info.QuarantinedAt,
		&info.FileSize,
		&info.FileHash,
		&threatsJSON,
		&info.Encrypted,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("quarantine entry not found: %s", quarantineID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get quarantine info: %w", err)
	}

	// Parse threats JSON
	if threatsJSON != "" {
		if err := json.Unmarshal([]byte(threatsJSON), &info.Threats); err != nil {
			info.Threats = []Threat{}
		}
	}

	// Update last accessed
	qm.db.ExecContext(ctx, "UPDATE quarantine SET last_accessed = ? WHERE id = ?", time.Now(), quarantineID)

	return &info, nil
}

// RestoreQuarantined restores a quarantined file to a destination
func (qm *QuarantineManager) RestoreQuarantined(ctx context.Context, quarantineID string, destination string) error {
	if !qm.enabled {
		return fmt.Errorf("quarantine not enabled")
	}

	// Get quarantine info and internal path
	query := `SELECT original_path, quarantine_path, encrypted FROM quarantine WHERE id = ?`
	var originalPath, quarantinePath string
	var encrypted bool

	err := qm.db.QueryRowContext(ctx, query, quarantineID).Scan(&originalPath, &quarantinePath, &encrypted)
	if err == sql.ErrNoRows {
		return fmt.Errorf("quarantine entry not found: %s", quarantineID)
	}
	if err != nil {
		return fmt.Errorf("failed to get quarantine info: %w", err)
	}

	// Check if quarantine file exists
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		return fmt.Errorf("quarantined file not found: %s", quarantinePath)
	}

	// Use original path if no destination specified
	if destination == "" {
		destination = originalPath
	}

	// Create parent directory if needed
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Restore file
	if encrypted {
		// Decrypt and restore
		if err := qm.decryptFile(quarantinePath, destination); err != nil {
			return fmt.Errorf("failed to decrypt file: %w", err)
		}
	} else {
		// Copy file back
		if err := copyFile(quarantinePath, destination); err != nil {
			return fmt.Errorf("failed to restore file: %w", err)
		}
	}

	// Restore original permissions (default to 0644 for safety)
	os.Chmod(destination, 0644)

	// Update restore count
	qm.db.ExecContext(ctx, "UPDATE quarantine SET restore_count = restore_count + 1 WHERE id = ?", quarantineID)

	return nil
}

// DeleteQuarantined permanently deletes a quarantined file
func (qm *QuarantineManager) DeleteQuarantined(ctx context.Context, quarantineID string) error {
	if !qm.enabled {
		return fmt.Errorf("quarantine not enabled")
	}

	// Get quarantine path from database
	var quarantinePath string
	err := qm.db.QueryRowContext(ctx, "SELECT quarantine_path FROM quarantine WHERE id = ?", quarantineID).Scan(&quarantinePath)
	if err == sql.ErrNoRows {
		return fmt.Errorf("quarantine entry not found: %s", quarantineID)
	}
	if err != nil {
		return fmt.Errorf("failed to get quarantine info: %w", err)
	}

	// Delete physical file
	if err := os.Remove(quarantinePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete quarantined file: %w", err)
	}

	// Delete database entry
	_, err = qm.db.ExecContext(ctx, "DELETE FROM quarantine WHERE id = ?", quarantineID)
	if err != nil {
		return fmt.Errorf("failed to delete quarantine metadata: %w", err)
	}

	return nil
}

// CleanQuarantine removes old quarantined files based on retention period
func (qm *QuarantineManager) CleanQuarantine(ctx context.Context, olderThan time.Duration) (int, error) {
	if !qm.enabled {
		return 0, fmt.Errorf("quarantine not enabled")
	}

	cutoff := time.Now().Add(-olderThan)

	// Get files to delete
	query := `SELECT id, quarantine_path FROM quarantine WHERE quarantined_at < ?`
	rows, err := qm.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to query old quarantines: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id, path string
		if err := rows.Scan(&id, &path); err != nil {
			continue
		}

		// Delete physical file
		os.Remove(path)

		// Delete database entry
		qm.db.ExecContext(ctx, "DELETE FROM quarantine WHERE id = ?", id)
		count++
	}

	return count, nil
}

// encryptFile encrypts a file using AES-256-GCM
func (qm *QuarantineManager) encryptFile(source, dest string) error {
	// Read source file
	plaintext, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	// Generate encryption key from config or use default
	key := qm.getEncryptionKey()

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Write encrypted file
	return os.WriteFile(dest, ciphertext, 0600)
}

// decryptFile decrypts a file using AES-256-GCM
func (qm *QuarantineManager) decryptFile(source, dest string) error {
	// Read encrypted file
	ciphertext, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	// Get encryption key
	key := qm.getEncryptionKey()

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// Write decrypted file
	return os.WriteFile(dest, plaintext, 0600)
}

// getEncryptionKey derives an encryption key from config or generates default
func (qm *QuarantineManager) getEncryptionKey() []byte {
	// In production, this should come from secure config or key management
	// For now, derive from machine-specific data
	hostname, _ := os.Hostname()
	keySource := fmt.Sprintf("aftersec-quarantine-%s", hostname)
	hash := sha256.Sum256([]byte(keySource))
	return hash[:]
}

// calculateFileHash computes SHA256 hash of a file
func calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
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

// Close closes the quarantine manager
func (qm *QuarantineManager) Close() error {
	if qm.enabled && qm.db != nil {
		return qm.db.Close()
	}
	return nil
}
