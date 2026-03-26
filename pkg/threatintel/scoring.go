package threatintel

import (
	"aftersec/pkg/core"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
)

// CalculateThreatLevel computes a 0-10 threat score based on security findings
func CalculateThreatLevel(findings []core.Finding) int {
	score := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for _, finding := range findings {
		if finding.Passed {
			continue // Skip passed findings
		}

		switch finding.Severity {
		case core.VeryHigh:
			criticalCount++
			score += 3
		case core.High:
			highCount++
			score += 2
		case core.Med:
			mediumCount++
			score += 1
		case core.Low, core.LogOnly:
			score += 0 // Low/log-only severity doesn't contribute
		}
	}

	// Cap at 10
	if score > 10 {
		score = 10
	}

	// Special case: If there are 3+ critical findings, automatically set to 10
	if criticalCount >= 3 {
		score = 10
	}

	return score
}

// CalculateFileThreatLevel determines threat level for a specific file
func CalculateFileThreatLevel(filePath string, isYaraMatch bool, isSigned bool, fileSize int64) int {
	score := 0

	// YARA match is a strong indicator
	if isYaraMatch {
		score += 8
	}

	// Unsigned binaries are suspicious
	if !isSigned {
		score += 2
	}

	// Check file location (high-risk directories)
	lowerPath := strings.ToLower(filePath)
	if strings.Contains(lowerPath, "/tmp/") ||
		strings.Contains(lowerPath, "/var/tmp/") ||
		strings.Contains(lowerPath, "/.") || // Hidden directories
		strings.Contains(lowerPath, "/downloads/") {
		score += 1
	}

	// Suspicious file sizes
	if fileSize > 0 && fileSize < 100 {
		score += 1 // Very small binaries are suspicious
	}

	// Cap at 10
	if score > 10 {
		score = 10
	}

	return score
}

// HashFile calculates the SHA256 hash of a file
func HashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// IsSignedBinary checks if a binary has a valid code signature
func IsSignedBinary(filePath string) bool {
	// This is a simplified check - in production, use forensics.VerifySignature()
	// For now, we'll check if it's in a system directory (likely signed)
	lowerPath := strings.ToLower(filePath)
	return strings.HasPrefix(lowerPath, "/system/") ||
		strings.HasPrefix(lowerPath, "/usr/bin/") ||
		strings.HasPrefix(lowerPath, "/usr/sbin/") ||
		strings.HasPrefix(lowerPath, "/applications/")
}
