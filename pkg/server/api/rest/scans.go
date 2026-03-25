package rest

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"aftersec/pkg/server/repository"
)

type CreateScanRequest struct {
	EndpointID    string     `json:"endpoint_id"`
	ClientScanID  string     `json:"client_scan_id"`
	ScanType      string     `json:"scan_type"`
	Status        string     `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	FindingsCount int        `json:"findings_count"`
	CriticalCount int        `json:"critical_count"`
	HighCount     int        `json:"high_count"`
	MediumCount   int        `json:"medium_count"`
	LowCount      int        `json:"low_count"`
	PassedCount   int        `json:"passed_count"`
}

func (rt *Router) handleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rt.listScans(w, r)
	case http.MethodPost:
		rt.createScan(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (rt *Router) handleScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		http.Error(w, "Missing scan ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rt.getScan(w, r, scanID)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (rt *Router) listScans(w http.ResponseWriter, r *http.Request) {
	endpointID := r.URL.Query().Get("endpoint_id")
	orgID := r.URL.Query().Get("org_id")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	scans, err := rt.repos.Scans.List(r.Context(), endpointID, orgID, limit)
	if err != nil {
		http.Error(w, "Failed to list scans", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func (rt *Router) getScan(w http.ResponseWriter, r *http.Request, id string) {
	scan, err := rt.repos.Scans.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to get scan", http.StatusInternalServerError)
		return
	}
	if scan == nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func (rt *Router) createScan(w http.ResponseWriter, r *http.Request) {
	var req CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.EndpointID == "" || req.ClientScanID == "" {
		http.Error(w, "Missing required fields: endpoint_id, client_scan_id", http.StatusBadRequest)
		return
	}

	orgID := r.Context().Value("organization_id")
	if orgID == nil {
		orgID = "default-org"
	}

	scan := &repository.Scan{
		OrganizationID: orgID.(string),
		EndpointID:     req.EndpointID,
		ClientScanID:   req.ClientScanID,
		ScanType:       req.ScanType,
		Status:         req.Status,
		StartedAt:      req.StartedAt,
		CompletedAt:    req.CompletedAt,
		FindingsCount:  req.FindingsCount,
		CriticalCount:  req.CriticalCount,
		HighCount:      req.HighCount,
		MediumCount:    req.MediumCount,
		LowCount:       req.LowCount,
		PassedCount:    req.PassedCount,
	}

	if err := rt.repos.Scans.Create(r.Context(), scan); err != nil {
		http.Error(w, "Failed to create scan", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(scan)
}
