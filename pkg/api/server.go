package api

import (
	"aftersec/pkg/client/storage"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func StartServer(port int, mgr storage.Manager) error {
	cfg, err := mgr.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return fmt.Errorf("API key not configured")
	}

	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			providedKey := parts[1]
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(cfg.APIKey)) != 1 {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}

			next(w, r)
		}
	}

	http.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"running"}`))
	})

	http.HandleFunc("/api/v1/posture", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		latest, err := mgr.GetLatest()
		if err != nil || latest == nil {
			http.Error(w, `{"error":"no baseline found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(latest); err != nil {
			http.Error(w, `{"error":"encoding failed"}`, http.StatusInternalServerError)
		}
	}))

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("Enterprise API listening on %s (requires Bearer token)\n", addr)
	fmt.Printf("API Key: %s\n", cfg.APIKey)
	return http.ListenAndServe(addr, nil)
}
