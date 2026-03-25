package rest

import (
	"encoding/json"
	"net/http"

	"aftersec/pkg/server/auth"
	"aftersec/pkg/server/repository"
)

// Router encapsulates the HTTP routing logic for the management UI
type Router struct {
	mux *http.ServeMux
	repos *repository.Repositories
}

// NewRouter initializes a fresh API layout
func NewRouter(jwtManager *auth.JWTManager, repos *repository.Repositories) *Router {
	mux := http.NewServeMux()

	// Public Health Endpoint
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "operational", "version": "1.0.0"})
	})

	router := &Router{mux: mux, repos: repos}

	// Organizations API
	mux.HandleFunc("/api/v1/organizations", jwtManager.HTTPMiddleware(router.handleOrganizations))
	mux.HandleFunc("/api/v1/organizations/", jwtManager.HTTPMiddleware(router.handleOrganization))

	// Endpoints API
	mux.HandleFunc("/api/v1/endpoints", jwtManager.HTTPMiddleware(router.handleEndpoints))
	mux.HandleFunc("/api/v1/endpoints/", jwtManager.HTTPMiddleware(router.handleEndpoint))

	// Scans API
	mux.HandleFunc("/api/v1/scans", jwtManager.HTTPMiddleware(router.handleScans))
	mux.HandleFunc("/api/v1/scans/", jwtManager.HTTPMiddleware(router.handleScan))

	// MDM Remote Action Webhook (Lost Device, Quarantine)
	mux.HandleFunc("/api/v1/endpoints/action", jwtManager.HTTPMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		// Stub: Decodes the external payload, and dispatches the Command via Redis PubSub
		// which the active gRPC stream picks up and rapidly shoots down to the client.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"status": "command_queued",
			"delivery_target": "sub-second",
		})
	}))

	return router
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
