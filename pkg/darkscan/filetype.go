package darkscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// FileTypeDetector wraps file type identification
type FileTypeDetector struct {
	enabled bool
}

// FileTypeResult represents file type identification results
type FileTypeResult struct {
	FilePath         string
	DetectedType     string
	DetectedMIME     string
	Extension        string
	ExtensionMatches bool
	IsSpoofed        bool
	Confidence       float64
	Details          string
}

// NewFileTypeDetector creates a new file type detector
func NewFileTypeDetector(cfg *Config) (*FileTypeDetector, error) {
	if !cfg.FileType.Enabled {
		return &FileTypeDetector{enabled: false}, nil
	}

	return &FileTypeDetector{
		enabled: true,
	}, nil
}

// IdentifyFileType identifies the actual file type using magic bytes
func (f *FileTypeDetector) IdentifyFileType(ctx context.Context, path string) (*FileTypeResult, error) {
	if !f.enabled {
		return nil, fmt.Errorf("file type detection not enabled")
	}

	// Get file extension
	ext := filepath.Ext(path)

	// Read file header for magic byte analysis
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read first 512 bytes for detection
	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("failed to read file header: %w", err)
	}
	header = header[:n]

	// Detect file type using magic bytes
	detectedType, detectedExt, mime := detectFileType(header)

	// Check if extension matches detected type
	extensionMatches := f.extensionMatches(ext, detectedExt)
	isSpoofed := !extensionMatches && ext != "" && detectedExt != ""

	return &FileTypeResult{
		FilePath:         path,
		DetectedType:     detectedType,
		DetectedMIME:     mime,
		Extension:        ext,
		ExtensionMatches: extensionMatches,
		IsSpoofed:        isSpoofed,
		Confidence:       0.8, // Basic detection has moderate confidence
		Details:          fmt.Sprintf("Detected as %s based on magic bytes", detectedType),
	}, nil
}

// detectFileType performs basic magic byte detection
func detectFileType(header []byte) (fileType, ext, mime string) {
	if len(header) < 4 {
		return "unknown", "", "application/octet-stream"
	}

	// Check common file signatures
	switch {
	case header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04:
		return "ZIP Archive", ".zip", "application/zip"
	case header[0] == 0x1F && header[1] == 0x8B:
		return "GZIP Archive", ".gz", "application/gzip"
	case header[0] == 0x25 && header[1] == 0x50 && header[2] == 0x44 && header[3] == 0x46:
		return "PDF Document", ".pdf", "application/pdf"
	case header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF:
		return "JPEG Image", ".jpg", "image/jpeg"
	case header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47:
		return "PNG Image", ".png", "image/png"
	case header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46:
		return "GIF Image", ".gif", "image/gif"
	case header[0] == 0x7F && header[1] == 0x45 && header[2] == 0x4C && header[3] == 0x46:
		return "ELF Executable", "", "application/x-executable"
	case header[0] == 0x4D && header[1] == 0x5A: // MZ
		return "Windows Executable", ".exe", "application/x-msdownload"
	case header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE:
		return "Mach-O Executable", "", "application/x-mach-binary"
	case header[0] == 0xCA && header[1] == 0xFE && header[2] == 0xBA && header[3] == 0xBE:
		return "Mach-O Universal Binary", "", "application/x-mach-binary"
	default:
		return "unknown", "", "application/octet-stream"
	}
}

// VerifyExtension checks if file extension matches actual content
func (f *FileTypeDetector) VerifyExtension(ctx context.Context, path string) (bool, error) {
	if !f.enabled {
		return false, fmt.Errorf("file type detection not enabled")
	}

	result, err := f.IdentifyFileType(ctx, path)
	if err != nil {
		return false, err
	}

	return result.ExtensionMatches, nil
}

// DetectSpoofing scans directory for files with mismatched extensions
func (f *FileTypeDetector) DetectSpoofing(ctx context.Context, dirPath string, recursive bool) ([]*FileTypeResult, error) {
	if !f.enabled {
		return nil, fmt.Errorf("file type detection not enabled")
	}

	var spoofedFiles []*FileTypeResult

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			if !recursive && path != dirPath {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file is spoofed
		result, err := f.IdentifyFileType(ctx, path)
		if err != nil {
			// Log error but continue scanning
			fmt.Fprintf(os.Stderr, "Warning: failed to check %s: %v\n", path, err)
			return nil
		}

		if result.IsSpoofed {
			spoofedFiles = append(spoofedFiles, result)
		}

		return nil
	}

	if err := filepath.Walk(dirPath, walkFn); err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return spoofedFiles, nil
}

// extensionMatches checks if file extension matches detected type
func (f *FileTypeDetector) extensionMatches(fileExt, detectedExt string) bool {
	if fileExt == "" || detectedExt == "" {
		return true // Can't determine mismatch
	}

	// Normalize extensions (remove leading dot)
	if fileExt[0] == '.' {
		fileExt = fileExt[1:]
	}
	if detectedExt[0] == '.' {
		detectedExt = detectedExt[1:]
	}

	// Direct match
	if fileExt == detectedExt {
		return true
	}

	// Check common aliases
	aliases := map[string][]string{
		"jpg":  {"jpeg", "jpe"},
		"jpeg": {"jpg", "jpe"},
		"tif":  {"tiff"},
		"tiff": {"tif"},
		"htm":  {"html"},
		"html": {"htm"},
		"mpg":  {"mpeg"},
		"mpeg": {"mpg"},
	}

	if aliasGroup, ok := aliases[fileExt]; ok {
		for _, alias := range aliasGroup {
			if alias == detectedExt {
				return true
			}
		}
	}

	return false
}

// ValidateBeforeScan performs pre-scan validation on a file
// Returns error if file type is suspicious or spoofed
func (f *FileTypeDetector) ValidateBeforeScan(ctx context.Context, path string, detectSpoofing bool) error {
	if !f.enabled {
		return nil // Silently skip if disabled
	}

	result, err := f.IdentifyFileType(ctx, path)
	if err != nil {
		// Don't fail scan on detection error, just warn
		fmt.Fprintf(os.Stderr, "Warning: file type detection failed for %s: %v\n", path, err)
		return nil
	}

	// Check for spoofing if enabled
	if detectSpoofing && result.IsSpoofed {
		return fmt.Errorf("file extension spoofing detected: %s claims to be %s but is actually %s",
			filepath.Base(path), result.Extension, result.DetectedType)
	}

	return nil
}
