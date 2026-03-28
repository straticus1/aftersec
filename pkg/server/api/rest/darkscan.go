package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
		FilePath: r.URL.Query().Get("file_path"),
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
