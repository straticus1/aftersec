package rest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/response"
	"aftersec/pkg/server/auth"
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
	EndpointID string            `json:"endpoint_id"`
	Action     response.Action   `json:"action"`
	Arguments  map[string]string `json:"arguments,omitempty"`
}

// Threats: tenant, role, token audience, and executable arguments are never
// accepted outside the signed claims authorized from validated JWT context.
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
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.OrganizationID == "" || claims.Role == "" || claims.UserID == "" {
		http.Error(w, "Validated authorization claims are required", http.StatusUnauthorized)
		return
	}
	if rt.actionMinter == nil || rt.enterpriseSrv == nil {
		http.Error(w, "Remote response is not configured", http.StatusServiceUnavailable)
		return
	}

	cmdID, err := newCommandID()
	if err != nil {
		http.Error(w, "Unable to create remote command", http.StatusInternalServerError)
		return
	}
	token, err := rt.actionMinter.Mint(r.Context(), response.MintRequest{
		Role:       claims.Role,
		TenantID:   claims.OrganizationID,
		EndpointID: req.EndpointID,
		Action:     req.Action,
		Arguments:  req.Arguments,
	})
	if err != nil {
		http.Error(w, "Remote action is not authorized", http.StatusForbidden)
		return
	}
	if rt.actionAudit == nil {
		http.Error(w, "Remote response audit is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := rt.actionAudit.AppendDispatch(r.Context(), response.AuditEvent{
		CommandID:  cmdID,
		TenantID:   claims.OrganizationID,
		EndpointID: req.EndpointID,
		Action:     req.Action,
		Status:     "DISPATCH_REQUESTED",
		Timestamp:  time.Now(),
	}, claims.UserID); err != nil {
		http.Error(w, "Remote response audit is unavailable", http.StatusServiceUnavailable)
		return
	}
	cmd := &grpcapi.ServerCommand{
		CommandId: cmdID,
		Action:    "REMOTE_ACTION",
		Payload:   token,
	}

	if err := rt.enterpriseSrv.DispatchCommand(req.EndpointID, cmd); err != nil {
		auditErr := rt.actionAudit.AppendDispatch(r.Context(), response.AuditEvent{
			CommandID:  cmdID,
			TenantID:   claims.OrganizationID,
			EndpointID: req.EndpointID,
			Action:     req.Action,
			Status:     "DISPATCH_FAILED",
			Timestamp:  time.Now(),
		}, claims.UserID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		message := err.Error()
		if auditErr != nil {
			message = "dispatch failed and failure audit could not be persisted"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   message,
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

func newCommandID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
