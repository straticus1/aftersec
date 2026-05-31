package main

import (
	"aftersec/pkg/core"
	"aftersec/pkg/threatintel"
	"context"
	"log"
	"os"
	"path/filepath"
	"time"
)

// submitScanFindings submits threat intelligence from a scan to FileHashes.io
func submitScanFindings(fileHashesClient *threatintel.FileHashesClient, state *core.SecurityState) {
	if fileHashesClient == nil {
		return // FileHashes.io not configured
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Calculate overall threat level from findings
	threatLevel := threatintel.CalculateThreatLevel(state.Findings)

	// Submit hashes for suspicious executables found during scan
	submitted := 0
	for _, finding := range state.Findings {
		if finding.Passed || finding.Severity == core.LogOnly {
			continue // Skip passed or info-only findings
		}

		// Extract file paths from findings that mention executables
		filePath := extractFilePath(finding)
		if filePath == "" {
			continue
		}

		// Only submit executable files
		if !isExecutable(filePath) {
			continue
		}

		// Calculate hash
		hash, err := threatintel.HashFile(filePath)
		if err != nil {
			continue // Skip if we can't read the file
		}

		// Get file info
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		// Determine if signed
		isSigned := threatintel.IsSignedBinary(filePath)

		// Calculate file-specific threat level
		fileThreatLevel := threatintel.CalculateFileThreatLevel(
			filePath,
			false, // YARA match status would come from scan
			isSigned,
			fileInfo.Size(),
		)

		// Use max of scan threat level and file threat level
		if fileThreatLevel > threatLevel {
			fileThreatLevel = threatLevel
		}

		submission := &threatintel.HashSubmission{
			Hash:         hash,
			Algorithm:    "sha256",
			ThreatLevel:  fileThreatLevel,
			SignedStatus: isSigned,
			FileSize:     fileInfo.Size(),
			FileName:     filepath.Base(filePath),
			DetectedBy:   "aftersec_scan",
			Timestamp:    time.Now(),
		}

		// Get geolocation
		geo, err := threatintel.GetGeoLocation(ctx)
		if err == nil {
			submission.SubmittedCountry = geo.Country
			submission.SubmittedState = geo.State
			submission.SubmittedISP = geo.ISP
		}

		if err := fileHashesClient.SubmitHash(ctx, submission); err != nil {
			log.Printf("⚠️ [FILEHASHES] Failed to submit hash %s: %v", hash[:16], err)
		} else {
			submitted++
		}
	}

	if submitted > 0 {
		log.Printf("📤 [FILEHASHES] Submitted %d hashes to global threat intelligence", submitted)
	}
}

// extractFilePath attempts to extract a file path from a finding
func extractFilePath(finding core.Finding) string {
	// Check LogContext first (most detailed)
	if finding.LogContext != "" && isValidPath(finding.LogContext) {
		return finding.LogContext
	}

	// Check CurrentVal
	if isValidPath(finding.CurrentVal) {
		return finding.CurrentVal
	}

	return ""
}

// isValidPath checks if a string looks like a valid file path
func isValidPath(path string) bool {
	if path == "" || len(path) < 2 {
		return false
	}

	// Must start with / or contain /
	if path[0] != '/' && !contains(path, "/") {
		return false
	}

	// Check if file exists
	_, err := os.Stat(path)
	return err == nil
}

// isExecutable checks if a file is an executable binary
func isExecutable(path string) bool {
	ext := filepath.Ext(path)

	// macOS executables
	if ext == ".app" || ext == "" {
		info, err := os.Stat(path)
		if err != nil {
			return false
		}
		// Check if executable permission bit is set
		return info.Mode()&0111 != 0
	}

	return false
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
