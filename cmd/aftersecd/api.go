package main

import (
	"aftersec/pkg/client"
	"aftersec/pkg/darkscan"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type ScanRequest struct {
	Path string `json:"path"`
}

type HistoryRequest struct {
	Limit int `json:"limit"`
}

type SearchRequest struct {
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

// startDarkScanAPI exposes a REST API for remote malware scanning
func startDarkScanAPI(ctx context.Context, cfg *client.ClientConfig, dsClient interface {
	ScanWithReport(ctx context.Context, path string) (*darkscan.IntegrationReport, error)
}) {
	if dsClient == nil || !cfg.Daemon.DarkScan.APIEnabled {
		return
	}

	mux := http.NewServeMux()

	// Scan endpoint
	mux.HandleFunc("/api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if _, err := os.Stat(req.Path); os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		scanCtx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		report, err := dsClient.ScanWithReport(scanCtx, req.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report)
	})

	// History endpoint
	mux.HandleFunc("/api/v1/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cliClient, ok := dsClient.(*darkscan.CLIClient)
		if !ok || !cfg.Daemon.DarkScan.UseCLI {
			http.Error(w, "History requires CLI mode", http.StatusNotImplemented)
			return
		}

		limit := 50
		if r.Method == http.MethodPost {
			var req HistoryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Limit > 0 {
				limit = req.Limit
			}
		}

		historyCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		history, err := cliClient.History(historyCtx, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})

	// Search endpoint
	mux.HandleFunc("/api/v1/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cliClient, ok := dsClient.(*darkscan.CLIClient)
		if !ok || !cfg.Daemon.DarkScan.UseCLI {
			http.Error(w, "Search requires CLI mode", http.StatusNotImplemented)
			return
		}

		var req SearchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if req.Query == "" {
			http.Error(w, "Query is required", http.StatusBadRequest)
			return
		}

		limit := 50
		if req.Limit > 0 {
			limit = req.Limit
		}

		searchCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		results, err := cliClient.Search(searchCtx, req.Query, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	port := cfg.Daemon.DarkScan.APIPort
	if port == 0 {
		port = 8081
	}

	srv := &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: mux,
	}

	go func() {
		log.Printf("🚀 Starting DarkScan REST API on port %d...", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("⚠️ DarkScan API Server Error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
}
