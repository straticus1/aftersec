package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"aftersec/pkg/server/clamav"
)

// ClamAVHandler handles ClamAV definition distribution endpoints
type ClamAVHandler struct {
	storage *clamav.Storage
	updater *clamav.Updater
}

// NewClamAVHandler creates a new ClamAV endpoint handler
func NewClamAVHandler(storage *clamav.Storage, updater *clamav.Updater) *ClamAVHandler {
	return &ClamAVHandler{
		storage: storage,
		updater: updater,
	}
}

// HandleGetVersion returns the current definition version metadata
func (h *ClamAVHandler) HandleGetVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata, err := h.updater.GetMetadata()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get metadata: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// HandleGetLatestBundle returns a compressed tarball of all definitions
func (h *ClamAVHandler) HandleGetLatestBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	bundle, size, err := h.storage.GetLatestBundle()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create bundle: %v", err), http.StatusInternalServerError)
		return
	}
	defer bundle.Close()

	metadata, _ := h.updater.GetMetadata()
	modTime := time.Now()
	if metadata != nil {
		modTime = metadata.UpdatedAt
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=clamav-definitions.tar.gz")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))

	http.ServeContent(w, r, "clamav-definitions.tar.gz", modTime, bundle.(io.ReadSeeker))
}

// HandleGetDefinitionFile returns a specific definition file
func (h *ClamAVHandler) HandleGetDefinitionFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract filename from path: /api/v1/clamav/definitions/main.cvd
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	filename := parts[len(parts)-1]

	// Validate filename extension
	ext := filepath.Ext(filename)
	if ext != ".cvd" && ext != ".cld" {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	file, size, err := h.storage.GetDefinitionFile(filename)
	if err != nil {
		http.Error(w, fmt.Sprintf("File not found: %v", err), http.StatusNotFound)
		return
	}
	defer file.(io.ReadCloser).Close()

	metadata, _ := h.updater.GetMetadata()
	modTime := time.Now()
	if metadata != nil {
		modTime = metadata.UpdatedAt
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))

	http.ServeContent(w, r, filename, modTime, file)
}

// HandleListDefinitions returns a list of available definition files
func (h *ClamAVHandler) HandleListDefinitions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	files, err := h.storage.ListDefinitions()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list definitions: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files": files,
		"count": len(files),
	})
}

// HandleForceUpdate triggers an immediate definition update
func (h *ClamAVHandler) HandleForceUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.updater.ForceUpdate(r.Context()); err != nil {
		http.Error(w, fmt.Sprintf("Update failed: %v", err), http.StatusInternalServerError)
		return
	}

	metadata, _ := h.updater.GetMetadata()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"message":  "Definitions updated successfully",
		"metadata": metadata,
	})
}
