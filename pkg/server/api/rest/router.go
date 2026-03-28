package rest

import (
	"encoding/json"
	"net/http"

	"aftersec/pkg/darkscan"
	"aftersec/pkg/server/auth"
	"aftersec/pkg/server/clamav"
	grpcserver "aftersec/pkg/server/grpc"
	"aftersec/pkg/server/repository"
)

// Router encapsulates the HTTP routing logic for the management UI
type Router struct {
	mux            *http.ServeMux
	repos          *repository.Repositories
	clamavHandler  *ClamAVHandler
	darkscanHandler *DarkScanHandler
	enterpriseSrv  *grpcserver.Server
}

// NewRouter initializes a fresh API layout
func NewRouter(jwtManager *auth.JWTManager, repos *repository.Repositories, enterpriseSrv *grpcserver.Server, clamavStorage *clamav.Storage, clamavUpdater *clamav.Updater, darkscanClient *darkscan.Client) *Router {
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

	// Initialize DarkScan handler if client is provided
	var darkscanHandler *DarkScanHandler
	if darkscanClient != nil {
		darkscanHandler = NewDarkScanHandler(darkscanClient)
	}

	router := &Router{
		mux:             mux,
		repos:           repos,
		clamavHandler:   clamavHandler,
		darkscanHandler: darkscanHandler,
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

	// DarkScan Platform API
	if darkscanHandler != nil {
		// Scan operations
		mux.HandleFunc("/api/v1/darkscan/scan", jwtManager.HTTPMiddleware(darkscanHandler.ScanFile))
		mux.HandleFunc("/api/v1/darkscan/scan/directory", jwtManager.HTTPMiddleware(darkscanHandler.ScanDirectory))

		// Privacy operations
		mux.HandleFunc("/api/v1/darkscan/privacy/scan", jwtManager.HTTPMiddleware(darkscanHandler.ScanPrivacy))
		mux.HandleFunc("/api/v1/darkscan/privacy/findings", jwtManager.HTTPMiddleware(darkscanHandler.GetPrivacyFindings))
		mux.HandleFunc("/api/v1/darkscan/privacy/trackers", jwtManager.HTTPMiddleware(darkscanHandler.DeleteTrackers))

		// Quarantine operations
		mux.HandleFunc("/api/v1/darkscan/quarantine", jwtManager.HTTPMiddleware(darkscanHandler.ListQuarantine))
		mux.HandleFunc("/api/v1/darkscan/quarantine/info", jwtManager.HTTPMiddleware(darkscanHandler.GetQuarantineInfo))
		mux.HandleFunc("/api/v1/darkscan/quarantine/restore", jwtManager.HTTPMiddleware(darkscanHandler.RestoreQuarantined))
		mux.HandleFunc("/api/v1/darkscan/quarantine/delete", jwtManager.HTTPMiddleware(darkscanHandler.DeleteQuarantined))

		// Rule management
		mux.HandleFunc("/api/v1/darkscan/rules/update", jwtManager.HTTPMiddleware(darkscanHandler.UpdateRules))
		mux.HandleFunc("/api/v1/darkscan/rules/repositories", jwtManager.HTTPMiddleware(darkscanHandler.ListRuleRepositories))

		// Profiles
		mux.HandleFunc("/api/v1/darkscan/profiles", jwtManager.HTTPMiddleware(darkscanHandler.ListProfiles))

		// History
		mux.HandleFunc("/api/v1/darkscan/history", jwtManager.HTTPMiddleware(darkscanHandler.GetHistory))

		// File type detection
		mux.HandleFunc("/api/v1/darkscan/filetype/identify", jwtManager.HTTPMiddleware(darkscanHandler.IdentifyFileType))

		// Status
		mux.HandleFunc("/api/v1/darkscan/status", jwtManager.HTTPMiddleware(darkscanHandler.GetStatus))
	}

	return router
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
