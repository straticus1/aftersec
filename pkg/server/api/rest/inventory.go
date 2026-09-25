package rest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
	"unicode"

	"aftersec/pkg/server/repository"
)

const maxInventoryBody = 8 * 1024

// Threats: a Windows reporter presents one organization-scoped enrollment code
// and a bounded posture document. The handler cannot set enrollment status,
// attach a certificate, or supply a hardware quote. A bad, expired, reused, or
// oversized report is rejected. The code is hashed before it reaches storage
// and is not written to the response or the log.

type inventoryCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}

type inventoryRequest struct {
	OrganizationID string           `json:"organization_id"`
	Code           string           `json:"code"`
	Hostname       string           `json:"hostname"`
	OSVersion      string           `json:"os_version"`
	LastBoot       string           `json:"last_boot"`
	Checks         []inventoryCheck `json:"checks"`
}

type inventoryPosture struct {
	LastBoot string           `json:"last_boot"`
	Checks   []inventoryCheck `json:"checks"`
}

func (rt *Router) handleInventoryWindows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if rt.repos == nil || rt.repos.Endpoints == nil {
		http.Error(w, "inventory is not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxInventoryBody))
	if err != nil {
		http.Error(w, "inventory report was rejected", http.StatusBadRequest)
		return
	}
	report, posture, err := decodeInventory(body, time.Now())
	if err != nil {
		http.Error(w, "inventory report was rejected", http.StatusBadRequest)
		return
	}
	observed := time.Now()
	id, err := rt.repos.Endpoints.RegisterInventory(r.Context(), repository.InventoryInput{
		OrganizationID: report.OrganizationID,
		CodeDigest:     sha256.Sum256([]byte(report.Code)),
		Hostname:       report.Hostname,
		OSVersion:      report.OSVersion,
		ObservedAt:     observed,
		Posture:        posture,
	})
	if errors.Is(err, repository.ErrInventoryCode) {
		http.Error(w, "inventory code is invalid", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "inventory report was rejected", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"id":                id,
		"enrollment_status": repository.InventoryStatus,
	}); err != nil {
		return
	}
}

func decodeInventory(body []byte, now time.Time) (inventoryRequest, []byte, error) {
	var report inventoryRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil || dec.More() {
		return inventoryRequest{}, nil, errInventory
	}
	if !validUUID(report.OrganizationID) || !validSecret(report.Code) || !validLabel(report.Hostname, 255) || !validLabel(report.OSVersion, 128) {
		return inventoryRequest{}, nil, errInventory
	}
	boot, err := time.Parse(time.RFC3339, report.LastBoot)
	if err != nil || boot.After(now.Add(2*time.Minute)) {
		return inventoryRequest{}, nil, errInventory
	}
	if err := validChecks(report.Checks); err != nil {
		return inventoryRequest{}, nil, err
	}
	posture, err := json.Marshal(inventoryPosture{LastBoot: boot.UTC().Format(time.RFC3339), Checks: report.Checks})
	if err != nil {
		return inventoryRequest{}, nil, errInventory
	}
	return report, posture, nil
}

var errInventory = errors.New("inventory report was rejected")

func validChecks(checks []inventoryCheck) error {
	if len(checks) != 2 {
		return errInventory
	}
	seen := map[string]bool{}
	for _, check := range checks {
		if seen[check.Name] || (check.Name != "Defender real-time protection" && check.Name != "Windows Firewall profiles") {
			return errInventory
		}
		seen[check.Name] = true
		if len(check.Error) > 256 || stringsHasControl(check.Error) {
			return errInventory
		}
		if check.Passed && check.Error != "" {
			return errInventory
		}
	}
	return nil
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
				return false
			}
		}
	}
	return true
}

func validSecret(value string) bool {
	if len(value) < 8 || len(value) > 128 || stringsHasControl(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func validLabel(value string, max int) bool {
	if len(value) == 0 || len(value) > max || stringsHasControl(value) {
		return false
	}
	for _, r := range value {
		if r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func stringsHasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
