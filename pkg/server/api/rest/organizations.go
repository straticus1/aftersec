package rest

import (
	"encoding/json"
	"net/http"

	"aftersec/pkg/server/repository"
)

type CreateOrganizationRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	LicenseTier string `json:"license_tier"`
}

type UpdateOrganizationRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	LicenseTier string `json:"license_tier"`
}

func (rt *Router) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rt.listOrganizations(w, r)
	case http.MethodPost:
		rt.createOrganization(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (rt *Router) handleOrganization(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("id")
	if orgID == "" {
		http.Error(w, "Missing organization ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rt.getOrganization(w, r, orgID)
	case http.MethodPut:
		rt.updateOrganization(w, r, orgID)
	case http.MethodDelete:
		rt.deleteOrganization(w, r, orgID)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (rt *Router) listOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := rt.repos.Organizations.List(r.Context())
	if err != nil {
		http.Error(w, "Failed to list organizations", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orgs)
}

func (rt *Router) getOrganization(w http.ResponseWriter, r *http.Request, id string) {
	org, err := rt.repos.Organizations.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, "Failed to get organization", http.StatusInternalServerError)
		return
	}
	if org == nil {
		http.Error(w, "Organization not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

func (rt *Router) createOrganization(w http.ResponseWriter, r *http.Request) {
	var req CreateOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Slug == "" {
		http.Error(w, "Missing required fields: name, slug", http.StatusBadRequest)
		return
	}

	if req.LicenseTier == "" {
		req.LicenseTier = "basic"
	}

	org := &repository.Organization{
		Name:        req.Name,
		Slug:        req.Slug,
		LicenseTier: req.LicenseTier,
	}

	if err := rt.repos.Organizations.Create(r.Context(), org); err != nil {
		http.Error(w, "Failed to create organization", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(org)
}

func (rt *Router) updateOrganization(w http.ResponseWriter, r *http.Request, id string) {
	var req UpdateOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	org := &repository.Organization{
		ID:          id,
		Name:        req.Name,
		Slug:        req.Slug,
		LicenseTier: req.LicenseTier,
	}

	if err := rt.repos.Organizations.Update(r.Context(), org); err != nil {
		http.Error(w, "Failed to update organization", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(org)
}

func (rt *Router) deleteOrganization(w http.ResponseWriter, r *http.Request, id string) {
	if err := rt.repos.Organizations.Delete(r.Context(), id); err != nil {
		http.Error(w, "Failed to delete organization", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
