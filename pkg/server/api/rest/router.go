package rest

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/billing"
	"aftersec/pkg/darkscan"
	"aftersec/pkg/ratelimit"
	"aftersec/pkg/server/auth"
	"aftersec/pkg/server/clamav"
	grpcserver "aftersec/pkg/server/grpc"
	"aftersec/pkg/server/repository"
	"github.com/redis/go-redis/v9"
)

// enterpriseServer is the subset of grpcserver.Server used by the REST layer.
type enterpriseServer interface {
	DispatchCommand(endpointID string, cmd *grpcapi.ServerCommand) error
	SetPendingSigmaRule(rule string)
}

// Router encapsulates the HTTP routing logic for the management UI
type Router struct {
	mux             *http.ServeMux
	repos           *repository.Repositories
	clamavHandler   *ClamAVHandler
	darkscanHandler *DarkScanHandler
	enterpriseSrv   enterpriseServer
	stripeClient    *billing.Client
	banditLimiter   *ratelimit.RedisRateLimiter
	darkwebLimiter  *ratelimit.RedisRateLimiter
}

// NewRouter initializes a fresh API layout.
// redisClient is optional: pass nil to disable rate limiting.
func NewRouter(jwtManager *auth.JWTManager, repos *repository.Repositories, enterpriseSrv *grpcserver.Server, clamavStorage *clamav.Storage, clamavUpdater *clamav.Updater, darkscanClient *darkscan.Client, redisClient *redis.Client) *Router {
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

	var stripeClient *billing.Client
	if key := os.Getenv("STRIPE_SECRET_KEY"); key != "" {
		stripeClient = billing.NewClient(key)
		if p := os.Getenv("STRIPE_PRICE_PROFESSIONAL"); p != "" {
			billing.PriceIDs["professional"] = p
		}
		if p := os.Getenv("STRIPE_PRICE_ENTERPRISE"); p != "" {
			billing.PriceIDs["enterprise"] = p
		}
	}

	router := &Router{
		mux:             mux,
		repos:           repos,
		enterpriseSrv:   enterpriseSrv,
		stripeClient:    stripeClient,
		clamavHandler:   clamavHandler,
		darkscanHandler: darkscanHandler,
	}

	if redisClient != nil {
		// 10 req/min for AI queries; 20 req/min for dark web intel
		router.banditLimiter = ratelimit.NewRedisRateLimiter(redisClient, "rl:bandit", 10, time.Minute/10)
		router.darkwebLimiter = ratelimit.NewRedisRateLimiter(redisClient, "rl:darkweb", 20, time.Minute/20)
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
		router.withRateLimit(router.banditLimiter,
			router.RequireTier(TierProfessional)(HandleBanditQuery))))

	// Dark Web Intelligence API (requires Professional tier)
	mux.HandleFunc("/api/v1/darkweb/alerts", jwtManager.HTTPMiddleware(
		router.withRateLimit(router.darkwebLimiter,
			router.RequireTier(TierProfessional)(HandleDarkWebAlerts))))
	mux.HandleFunc("/api/v1/darkweb/config", jwtManager.HTTPMiddleware(
		router.withRateLimit(router.darkwebLimiter,
			router.RequireTier(TierProfessional)(HandleDarkWebConfig))))

	// AI Budget and Usage API (all tiers)
	mux.HandleFunc("/api/v1/ai/budget", jwtManager.HTTPMiddleware(router.handleAIBudget))
	mux.HandleFunc("/api/v1/ai/usage", jwtManager.HTTPMiddleware(router.handleAIUsage))

	// Tier Management API
	mux.HandleFunc("/api/v1/organizations/tier", jwtManager.HTTPMiddleware(router.handleGetTierInfo))
	mux.HandleFunc("/api/v1/organizations/upgrade", jwtManager.HTTPMiddleware(router.handleUpgradeTier))

	// MDM Remote Action — dispatches a command to the endpoint's active gRPC stream
	mux.HandleFunc("/api/v1/endpoints/action", jwtManager.HTTPMiddleware(router.handleEndpointAction))

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
		mux.HandleFunc("/api/v1/darkscan/scan/volume", jwtManager.HTTPMiddleware(darkscanHandler.ScanVolume))
		mux.HandleFunc("/api/v1/darkscan/scan/multiple", jwtManager.HTTPMiddleware(darkscanHandler.ScanMultiplePaths))

		// Volume operations
		mux.HandleFunc("/api/v1/darkscan/volumes", jwtManager.HTTPMiddleware(darkscanHandler.ListVolumes))

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
		mux.HandleFunc("/api/v1/darkscan/filetype/verify", jwtManager.HTTPMiddleware(darkscanHandler.VerifyExtension))
		mux.HandleFunc("/api/v1/darkscan/filetype/spoofing", jwtManager.HTTPMiddleware(darkscanHandler.DetectSpoofing))

		// Steganography detection
		mux.HandleFunc("/api/v1/darkscan/stego/detect", jwtManager.HTTPMiddleware(darkscanHandler.DetectSteganography))
		mux.HandleFunc("/api/v1/darkscan/stego/batch", jwtManager.HTTPMiddleware(darkscanHandler.BatchDetectSteganography))

		// Container image scanning
		mux.HandleFunc("/api/v1/darkscan/container/scan", jwtManager.HTTPMiddleware(darkscanHandler.ScanContainerImage))

		// Status
		mux.HandleFunc("/api/v1/darkscan/status", jwtManager.HTTPMiddleware(darkscanHandler.GetStatus))
	}

	return router
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// withRateLimit wraps a handler with per-IP rate limiting.
// If limiter is nil (Redis not configured), the handler runs unrestricted.
func (r *Router) withRateLimit(limiter *ratelimit.RedisRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	if limiter == nil {
		return next
	}
	return func(w http.ResponseWriter, req *http.Request) {
		ip, _, _ := splitHostPort(req.RemoteAddr)
		allowed, err := limiter.TryConsume(req.Context(), ip)
		if err != nil {
			// Redis error — fail open so an outage doesn't block legitimate traffic
			next(w, req)
			return
		}
		if !allowed {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next(w, req)
	}
}

// splitHostPort splits host:port, returning host on error.
func splitHostPort(addr string) (host, port string, err error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}
