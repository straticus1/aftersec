package clamav

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Storage manages ClamAV definition file storage and retrieval
type Storage struct {
	storagePath string
}

// NewStorage creates a new storage manager
func NewStorage(storagePath string) *Storage {
	if storagePath == "" {
		storagePath = "/var/aftersec/clamav-defs"
	}
	return &Storage{storagePath: storagePath}
}

// GetDefinitionFile returns a specific definition file
func (s *Storage) GetDefinitionFile(filename string) (io.ReadSeeker, int64, error) {
	// Validate filename to prevent path traversal
	allowedFiles := map[string]bool{
		"main.cvd":     true,
		"main.cld":     true,
		"daily.cvd":    true,
		"daily.cld":    true,
		"bytecode.cvd": true,
		"bytecode.cld": true,
	}

	if !allowedFiles[filename] {
		return nil, 0, fmt.Errorf("invalid definition filename: %s", filename)
	}

	path := filepath.Join(s.storagePath, filename)
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open definition file: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, fmt.Errorf("failed to stat file: %w", err)
	}

	return file, info.Size(), nil
}

// GetLatestBundle creates and returns a compressed tarball of all definitions
func (s *Storage) GetLatestBundle() (io.ReadCloser, int64, error) {
	// Create temporary file for the bundle
	tmpFile, err := os.CreateTemp("", "clamav-bundle-*.tar.gz")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Ensure cleanup if we return early with error
	defer func() {
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	// Create gzip writer
	gzipWriter := gzip.NewWriter(tmpFile)
	defer gzipWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Add metadata.json
	if err = s.addFileToTar(tarWriter, "metadata.json"); err != nil {
		return nil, 0, err
	}

	// Add definition files
	defFiles := []string{"main.cvd", "main.cld", "daily.cvd", "daily.cld", "bytecode.cvd", "bytecode.cld"}
	for _, filename := range defFiles {
		path := filepath.Join(s.storagePath, filename)
		if _, err := os.Stat(path); err == nil {
			if err = s.addFileToTar(tarWriter, filename); err != nil {
				return nil, 0, err
			}
		}
	}

	// Close writers to flush
	if err = tarWriter.Close(); err != nil {
		return nil, 0, fmt.Errorf("failed to close tar writer: %w", err)
	}
	if err = gzipWriter.Close(); err != nil {
		return nil, 0, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Get file size
	info, err := tmpFile.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to stat bundle: %w", err)
	}

	// Seek back to start
	if _, err = tmpFile.Seek(0, 0); err != nil {
		return nil, 0, fmt.Errorf("failed to seek: %w", err)
	}

	// Return a cleanup reader that deletes the temp file when closed
	reader := &cleanupReader{
		file: tmpFile,
		path: tmpFile.Name(),
	}

	return reader, info.Size(), nil
}

// addFileToTar adds a file to the tar archive
func (s *Storage) addFileToTar(tarWriter *tar.Writer, filename string) error {
	path := filepath.Join(s.storagePath, filename)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", filename, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", filename, err)
	}

	header := &tar.Header{
		Name:    filename,
		Size:    info.Size(),
		Mode:    int64(info.Mode()),
		ModTime: info.ModTime(),
	}

	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}

	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("failed to write file to tar: %w", err)
	}

	return nil
}

// cleanupReader wraps a file and deletes it when closed
type cleanupReader struct {
	file *os.File
	path string
}

func (r *cleanupReader) Read(p []byte) (n int, err error) {
	return r.file.Read(p)
}

func (r *cleanupReader) Close() error {
	r.file.Close()
	os.Remove(r.path)
	return nil
}

// ListDefinitions returns a list of available definition files with metadata
func (s *Storage) ListDefinitions() ([]DefinitionFile, error) {
	files := []DefinitionFile{}
	defFiles := []string{"main.cvd", "main.cld", "daily.cvd", "daily.cld", "bytecode.cvd", "bytecode.cld"}

	for _, filename := range defFiles {
		path := filepath.Join(s.storagePath, filename)
		if info, err := os.Stat(path); err == nil {
			files = append(files, DefinitionFile{
				Name:      filename,
				SizeBytes: info.Size(),
				SizeMB:    float64(info.Size()) / (1024 * 1024),
				ModTime:   info.ModTime(),
			})
		}
	}

	return files, nil
}

// DefinitionFile represents a single ClamAV definition file
type DefinitionFile struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	SizeMB    float64   `json:"size_mb"`
	ModTime   time.Time `json:"mod_time"`
}
