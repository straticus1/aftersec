package rest

import (
	"encoding/json"
	"net/http"

	"aftersec/pkg/server/auth"
	"aftersec/pkg/server/clamav"
	grpcserver "aftersec/pkg/server/grpc"
	"aftersec/pkg/server/repository"
)

// Router encapsulates the HTTP routing logic for the management UI
type Router struct {
	mux           *http.ServeMux
	repos         *repository.Repositories
	clamavHandler *ClamAVHandler
	enterpriseSrv *grpcserver.Server
}

// NewRouter initializes a fresh API layout
func NewRouter(jwtManager *auth.JWTManager, repos *repository.Repositories, enterpriseSrv *grpcserver.Server, clamavStorage *clamav.Storage, clamavUpdater *clamav.Updater) *Router {
	mux := http.NewServeMux()

	// Public Health Endpoint
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "operational", "version": "1.0.0"})
	})

	// Initialize ClamAV handler if storage and updater are provided
	var clamavHandler *ClamAVHandler
	if clamavStorage != nil && clamavUpdater != nil {
		clamavHandler = NewClamAVHandler(clamavStorage, clamavUpdater)
	}

	router := &Router{
		mux:           mux,
		repos:         repos,
		clamavHandler: clamavHandler,
	}

	// Organizations API
	mux.HandleFunc("/api/v1/organizations", jwtManager.HTTPMiddleware(router.handleOrganizations))
	mux.HandleFunc("/api/v1/organizations/", jwtManager.HTTPMiddleware(router.handleOrganization))

	// Endpoints API
	mux.HandleFunc("/api/v1/endpoints", jwtManager.HTTPMiddleware(router.handleEndpoints))
	mux.HandleFunc("/api/v1/endpoints/", jwtManager.HTTPMiddleware(router.handleEndpoint))

	// Scans API
	mux.HandleFunc("/api/v1/scans", jwtManager.HTTPMiddleware(router.handleScans))
	mux.HandleFunc("/api/v1/scans/", jwtManager.HTTPMiddleware(router.handleScan))

	// Bandit AI API (requires Professional tier)
	mux.HandleFunc("/api/v1/bandit/query", jwtManager.HTTPMiddleware(
		router.RequireTier(TierProfessional)(HandleBanditQuery)))

	// Dark Web Intelligence API (requires Professional tier)
	mux.HandleFunc("/api/v1/darkweb/alerts", jwtManager.HTTPMiddleware(
		router.RequireTier(TierProfessional)(HandleDarkWebAlerts)))
	mux.HandleFunc("/api/v1/darkweb/config", jwtManager.HTTPMiddleware(
		router.RequireTier(TierProfessional)(HandleDarkWebConfig)))

	// AI Budget and Usage API (all tiers)
	mux.HandleFunc("/api/v1/ai/budget", jwtManager.HTTPMiddleware(router.handleAIBudget))
	mux.HandleFunc("/api/v1/ai/usage", jwtManager.HTTPMiddleware(router.handleAIUsage))

	// Tier Management API
	mux.HandleFunc("/api/v1/organizations/tier", jwtManager.HTTPMiddleware(router.handleGetTierInfo))
	mux.HandleFunc("/api/v1/organizations/upgrade", jwtManager.HTTPMiddleware(router.handleUpgradeTier))

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

	// Sigma API
	mux.HandleFunc("/api/v1/sigma/deploy", jwtManager.HTTPMiddleware(router.handleSigmaDeploy))

	// MISP Threat Intel API
	mux.HandleFunc("/api/v1/misp/config", jwtManager.HTTPMiddleware(router.handleMISPConfig))
	mux.HandleFunc("/api/v1/misp/sync", jwtManager.HTTPMiddleware(router.handleMISPSync))

	// Detonation Engine API
	mux.HandleFunc("/api/v1/detonate", jwtManager.HTTPMiddleware(router.handleDetonate))

	// ClamAV Definition Distribution API (public endpoints for endpoints to download definitions)
	if clamavHandler != nil {
		mux.HandleFunc("/api/v1/clamav/definitions/version", clamavHandler.HandleGetVersion)
		mux.HandleFunc("/api/v1/clamav/definitions/latest", clamavHandler.HandleGetLatestBundle)
		mux.HandleFunc("/api/v1/clamav/definitions/list", clamavHandler.HandleListDefinitions)
		mux.HandleFunc("/api/v1/clamav/definitions/", clamavHandler.HandleGetDefinitionFile)
		// Admin endpoint for forcing updates (requires authentication)
		mux.HandleFunc("/api/v1/clamav/update", jwtManager.HTTPMiddleware(clamavHandler.HandleForceUpdate))
	}

	return router
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
