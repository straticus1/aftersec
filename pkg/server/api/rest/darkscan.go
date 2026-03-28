package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"aftersec/pkg/darkscan"
)

// DarkScanHandler handles all DarkScan API endpoints
type DarkScanHandler struct {
	client *darkscan.Client
}

// NewDarkScanHandler creates a new DarkScan API handler
func NewDarkScanHandler(client *darkscan.Client) *DarkScanHandler {
	return &DarkScanHandler{client: client}
}

//
// Scan Operations
//

func (h *DarkScanHandler) ScanFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Timeout int    `json:"timeout,omitempty"` // seconds
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	timeout := 120 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	result, err := h.client.ScanFile(ctx, req.Path)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Scan failed: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *DarkScanHandler) ScanDirectory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
		Timeout   int    `json:"timeout,omitempty"` // seconds
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	timeout := 10 * time.Minute
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	results, err := h.client.ScanDirectory(ctx, req.Path, req.Recursive)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Directory scan failed: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"path":      req.Path,
			"recursive": req.Recursive,
			"results":   results,
			"total":     len(results),
		},
	})
}

//
// Privacy Operations
//

func (h *DarkScanHandler) ScanPrivacy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Browsers []string `json:"browsers"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Browsers) == 0 {
		req.Browsers = []string{"chrome", "firefox", "safari"}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	results, err := h.client.ScanBrowserPrivacy(ctx, req.Browsers)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Privacy scan failed: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    results,
	})
}

func (h *DarkScanHandler) GetPrivacyFindings(w http.ResponseWriter, r *http.Request) {
	filters := darkscan.PrivacyFilter{
		Browser:   r.URL.Query().Get("browser"),
		Type:      r.URL.Query().Get("type"),
		RiskLevel: r.URL.Query().Get("risk_level"),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	findings, err := h.client.ListPrivacyFindings(ctx, filters)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get findings: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    findings,
	})
}

func (h *DarkScanHandler) DeleteTrackers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Browser    string   `json:"browser"`
		TrackerIDs []string `json:"tracker_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Browser == "" || len(req.TrackerIDs) == 0 {
		respondError(w, http.StatusBadRequest, "browser and tracker_ids are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	err := h.client.RemoveTrackers(ctx, req.Browser, req.TrackerIDs)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to remove trackers: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Removed %d trackers", len(req.TrackerIDs)),
	})
}

//
// Quarantine Operations
//

func (h *DarkScanHandler) ListQuarantine(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	entries, err := h.client.ListQuarantine(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list quarantine: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"entries": entries,
			"total":   len(entries),
		},
	})
}

func (h *DarkScanHandler) GetQuarantineInfo(w http.ResponseWriter, r *http.Request) {
	quarantineID := r.URL.Query().Get("id")

	if quarantineID == "" {
		respondError(w, http.StatusBadRequest, "quarantine_id query parameter is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	info, err := h.client.GetQuarantineInfo(ctx, quarantineID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			respondError(w, http.StatusNotFound, "Quarantine entry not found")
		} else {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get quarantine info: %v", err))
		}
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    info,
	})
}

func (h *DarkScanHandler) RestoreQuarantined(w http.ResponseWriter, r *http.Request) {
	quarantineID := r.URL.Query().Get("id")

	if quarantineID == "" {
		respondError(w, http.StatusBadRequest, "quarantine_id query parameter is required")
		return
	}

	var req struct {
		Destination string `json:"destination,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	err := h.client.RestoreQuarantined(ctx, quarantineID, req.Destination)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			respondError(w, http.StatusNotFound, "Quarantine entry not found")
		} else {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to restore: %v", err))
		}
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "File restored successfully",
	})
}

func (h *DarkScanHandler) DeleteQuarantined(w http.ResponseWriter, r *http.Request) {
	quarantineID := r.URL.Query().Get("id")

	if quarantineID == "" {
		respondError(w, http.StatusBadRequest, "quarantine_id query parameter is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	err := h.client.DeleteQuarantined(ctx, quarantineID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			respondError(w, http.StatusNotFound, "Quarantine entry not found")
		} else {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete: %v", err))
		}
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Quarantined file deleted successfully",
	})
}

//
// Rule Management Operations
//

func (h *DarkScanHandler) UpdateRules(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	err := h.client.UpdateRules(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Rule update failed: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Rules updated successfully",
	})
}

func (h *DarkScanHandler) ListRuleRepositories(w http.ResponseWriter, r *http.Request) {
	repos, err := h.client.ListRuleRepositories()
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list repositories: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    repos,
	})
}

//
// Profile Operations
//

func (h *DarkScanHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.client.ListProfiles()
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list profiles: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    profiles,
	})
}

//
// History Operations
//

func (h *DarkScanHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	filters := darkscan.HistoryFilter{
		Infected: parseBoolQuery(r.URL.Query().Get("infected")),
		Limit:    100, // Default limit
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filters.Limit = limit
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	history, err := h.client.GetScanHistory(ctx, filters)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get history: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"entries": history,
			"total":   len(history),
		},
	})
}

//
// File Type Operations
//

func (h *DarkScanHandler) IdentifyFileType(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result, err := h.client.IdentifyFileType(ctx, req.Path)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("File type detection failed: %v", err))
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

//
// Steganography Operations
//

func (h *DarkScanHandler) DetectSteganography(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	result, err := h.client.DetectSteganography(ctx, req.Path)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *DarkScanHandler) BatchDetectSteganography(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Paths []string `json:"paths"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Paths) == 0 {
		respondError(w, http.StatusBadRequest, "paths array is required and must not be empty")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	results, err := h.client.BatchDetectSteganography(ctx, req.Paths)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    results,
	})
}

//
// Container Scanning Operations
//

func (h *DarkScanHandler) ScanContainerImage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ImageRef string `json:"image_ref"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ImageRef == "" {
		respondError(w, http.StatusBadRequest, "image_ref is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	result, err := h.client.ScanContainerImage(ctx, req.ImageRef)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

//
// File Type Operations (Enhanced)
//

func (h *DarkScanHandler) VerifyExtension(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	matches, err := h.client.VerifyExtension(ctx, req.Path)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"path":    req.Path,
			"matches": matches,
		},
	})
}

func (h *DarkScanHandler) DetectSpoofing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	results, err := h.client.DetectSpoofing(ctx, req.Path, req.Recursive)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    results,
	})
}

//
// Volume Operations
//

func (h *DarkScanHandler) ListVolumes(w http.ResponseWriter, r *http.Request) {
	volumes := detectAvailableVolumes()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"volumes": volumes,
			"total":   len(volumes),
		},
	})
}

func (h *DarkScanHandler) ScanVolume(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path      string   `json:"path"`
		Profile   string   `json:"profile"`
		Exclude   []string `json:"exclude"`
		Timeout   int      `json:"timeout,omitempty"` // seconds
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Path == "" {
		respondError(w, http.StatusBadRequest, "path is required")
		return
	}

	if req.Profile == "" {
		req.Profile = "standard"
	}

	timeout := 30 * time.Minute
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// For volume scans, we use ScanDirectory with recursive=true
	// This is similar to the scan-volume command
	results, err := h.client.ScanDirectory(ctx, req.Path, true)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("Volume scan failed: %v", err))
		return
	}

	infectedCount := 0
	totalThreats := 0
	for _, result := range results {
		if result.Infected {
			infectedCount++
			totalThreats += len(result.Threats)
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"volume_path":    req.Path,
			"profile":        req.Profile,
			"total_files":    len(results),
			"infected_files": infectedCount,
			"total_threats":  totalThreats,
			"results":        results,
		},
	})
}

func (h *DarkScanHandler) ScanMultiplePaths(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Paths     []string `json:"paths"`
		Profile   string   `json:"profile"`
		Recursive bool     `json:"recursive"`
		Timeout   int      `json:"timeout,omitempty"` // seconds
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Paths) == 0 {
		respondError(w, http.StatusBadRequest, "paths array is required and must not be empty")
		return
	}

	if req.Profile == "" {
		req.Profile = "standard"
	}

	timeout := 30 * time.Minute
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// Scan each path
	allResults := make(map[string]interface{})
	totalFiles := 0
	totalInfected := 0
	totalThreats := 0

	for _, path := range req.Paths {
		results, err := h.client.ScanDirectory(ctx, path, req.Recursive)
		if err != nil {
			allResults[path] = map[string]interface{}{
				"error": err.Error(),
			}
			continue
		}

		infectedCount := 0
		threatCount := 0
		for _, result := range results {
			if result.Infected {
				infectedCount++
				threatCount += len(result.Threats)
			}
		}

		totalFiles += len(results)
		totalInfected += infectedCount
		totalThreats += threatCount

		allResults[path] = map[string]interface{}{
			"total_files":    len(results),
			"infected_files": infectedCount,
			"total_threats":  threatCount,
			"results":        results,
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"paths":          req.Paths,
			"profile":        req.Profile,
			"total_files":    totalFiles,
			"infected_files": totalInfected,
			"total_threats":  totalThreats,
			"results":        allResults,
		},
	})
}

//
// Status Operations
//

func (h *DarkScanHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	connStatus := h.client.GetConnectionStatus()
	engines := h.client.GetEnabledEngines()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Get quarantine stats
	var quarantineCount int
	quarantineList, err := h.client.ListQuarantine(ctx)
	if err == nil {
		quarantineCount = len(quarantineList)
	}

	// Get history stats
	historyFilter := darkscan.HistoryFilter{Limit: 1000}
	history, _ := h.client.GetScanHistory(ctx, historyFilter)
	infectedCount := 0
	for _, entry := range history {
		if entry.Infected {
			infectedCount++
		}
	}

	status := map[string]interface{}{
		"connection": map[string]interface{}{
			"mode":             connStatus.Mode,
			"daemon_connected": connStatus.DaemonConnected,
		},
		"engines": map[string]interface{}{
			"enabled": engines,
			"count":   len(engines),
		},
		"quarantine": map[string]interface{}{
			"file_count": quarantineCount,
		},
		"hash_store": map[string]interface{}{
			"total_scans": len(history),
			"infected":    infectedCount,
			"clean":       len(history) - infectedCount,
		},
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    status,
	})
}

//
// Helper functions
//

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func parseBoolQuery(value string) *bool {
	if value == "" {
		return nil
	}
	b := value == "true" || value == "1"
	return &b
}

// Volume detection helper
type VolumeInfo struct {
	Path       string `json:"path"`
	Size       uint64 `json:"size,omitempty"`
	Available  uint64 `json:"available,omitempty"`
	Filesystem string `json:"filesystem,omitempty"`
	MountPoint string `json:"mount_point"`
}

func detectAvailableVolumes() []VolumeInfo {
	var volumes []VolumeInfo

	switch runtime.GOOS {
	case "darwin":
		// Root volume
		volumes = append(volumes, VolumeInfo{
			Path:       "/",
			MountPoint: "/",
			Filesystem: "apfs",
		})

		// Check /Volumes for mounted drives
		volumesDir := "/Volumes"
		if entries, err := os.ReadDir(volumesDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					volPath := filepath.Join(volumesDir, entry.Name())
					volumes = append(volumes, VolumeInfo{
						Path:       volPath,
						MountPoint: volPath,
					})
				}
			}
		}

		// Add System Data volume
		if info, err := os.Stat("/System/Volumes/Data"); err == nil && info.IsDir() {
			volumes = append(volumes, VolumeInfo{
				Path:       "/System/Volumes/Data",
				MountPoint: "/System/Volumes/Data",
				Filesystem: "apfs",
			})
		}

	case "linux":
		// Root
		volumes = append(volumes, VolumeInfo{
			Path:       "/",
			MountPoint: "/",
		})

		// Common mount points
		commonMounts := []string{"/home", "/mnt", "/media"}
		for _, mount := range commonMounts {
			if info, err := os.Stat(mount); err == nil && info.IsDir() {
				volumes = append(volumes, VolumeInfo{
					Path:       mount,
					MountPoint: mount,
				})
			}
		}

		// Check /media subdirectories
		if entries, err := os.ReadDir("/media"); err == nil {
			for _, userDir := range entries {
				userPath := filepath.Join("/media", userDir.Name())
				if subEntries, err := os.ReadDir(userPath); err == nil {
					for _, entry := range subEntries {
						if entry.IsDir() {
							volPath := filepath.Join(userPath, entry.Name())
							volumes = append(volumes, VolumeInfo{
								Path:       volPath,
								MountPoint: volPath,
							})
						}
					}
				}
			}
		}

	case "windows":
		// Check drive letters
		for drive := 'A'; drive <= 'Z'; drive++ {
			drivePath := fmt.Sprintf("%c:\\", drive)
			if info, err := os.Stat(drivePath); err == nil && info.IsDir() {
				volumes = append(volumes, VolumeInfo{
					Path:       drivePath,
					MountPoint: drivePath,
					Filesystem: "ntfs",
				})
			}
		}
	}

	return volumes
}
