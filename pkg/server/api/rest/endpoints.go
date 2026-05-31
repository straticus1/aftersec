package rest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/server/repository"
)

type UpdateEndpointRequest struct {
	Hostname         string `json:"hostname"`
	Platform         string `json:"platform"`
	EnrollmentStatus string `json:"enrollment_status"`
}

func (rt *Router) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rt.listEndpoints(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (rt *Router) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	endpointID := r.URL.Query().Get("id")
	if endpointID == "" {
		http.Error(w, "Missing endpoint ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rt.getEndpoint(w, r, endpointID)
	case http.MethodPut:
		rt.updateEndpoint(w, r, endpointID)
	case http.MethodDelete:
		rt.deleteEndpoint(w, r, endpointID)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (rt *Router) listEndpoints(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")

	endpoints, err := rt.repos.Endpoints.List(r.Context(), orgID)
	if err != nil {
		http.Error(w, "Failed to list endpoints", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoints)
}

func (rt *Router) getEndpoint(w http.ResponseWriter, r *http.Request, id string) {
	endpoint, err := rt.repos.Endpoints.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to get endpoint", http.StatusInternalServerError)
		return
	}
	if endpoint == nil {
		http.Error(w, "Endpoint not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoint)
}

func (rt *Router) updateEndpoint(w http.ResponseWriter, r *http.Request, id string) {
	var req UpdateEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	endpoint := &repository.Endpoint{
		ID:               id,
		Hostname:         req.Hostname,
		Platform:         req.Platform,
		EnrollmentStatus: req.EnrollmentStatus,
	}

	if err := rt.repos.Endpoints.Update(r.Context(), endpoint); err != nil {
		http.Error(w, "Failed to update endpoint", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoint)
}

func (rt *Router) deleteEndpoint(w http.ResponseWriter, r *http.Request, id string) {
	if err := rt.repos.Endpoints.Delete(r.Context(), id); err != nil {
		http.Error(w, "Failed to delete endpoint", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type EndpointActionRequest struct {
	EndpointID string `json:"endpoint_id"`
	Action     string `json:"action"`
	Payload    string `json:"payload"` // optional base64-encoded parameters
}

func (rt *Router) handleEndpointAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EndpointActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.EndpointID == "" || req.Action == "" {
		http.Error(w, "Missing required fields: endpoint_id, action", http.StatusBadRequest)
		return
	}

	cmdID := newCommandID()
	cmd := &grpcapi.ServerCommand{
		CommandId: cmdID,
		Action:    req.Action,
	}

	if err := rt.enterpriseSrv.DispatchCommand(req.EndpointID, cmd); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"command_id": cmdID,
		"status":     "command_queued",
		"delivery":   "sub-second",
	})
}

func newCommandID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
