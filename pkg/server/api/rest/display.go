package rest

import (
	"io"
	"net/http"

	"aftersec/pkg/server/auth"
)

// Threats: a frame is returned only to an operator in the tenant that stored
// it. The handler does not accept a filesystem path.
func (rt *Router) handleDisplayFrame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.OrganizationID == "" || (claims.Role != "admin" && claims.Role != "security_operator") {
		http.Error(w, "Display frames require an operator role", http.StatusForbidden)
		return
	}
	if rt.frames == nil {
		http.Error(w, "Display frames are not configured", http.StatusServiceUnavailable)
		return
	}
	f, err := rt.frames.Open(claims.OrganizationID, r.URL.Query().Get("endpoint_id"), r.URL.Query().Get("command_id"))
	if err != nil {
		http.Error(w, "Display frame is not available", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err = io.Copy(w, f); err != nil {
		return
	}
}
