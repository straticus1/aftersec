package darkscan

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

// NewDarkScanClient creates a DarkScan client with intelligent mode selection.
// It tries daemon connection first (if enabled), then falls back to library mode.
//
// Connection strategy:
// 1. Check if daemon mode is enabled in config
// 2. If enabled, try Unix socket connection (2s timeout)
// 3. If socket fails, try TCP connection (2s timeout)
// 4. If both fail and fallback enabled, create library client
// 5. If fallback disabled, return error
//
// The returned client implements the DarkScanClient interface, abstracting
// the underlying connection type from consumers.
func NewDarkScanClient(cfg *Config) (DarkScanClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("darkscan: config cannot be nil")
	}

	if !cfg.Enabled {
		return nil, fmt.Errorf("darkscan: integration disabled in configuration")
	}

	// Legacy CLI mode support (deprecated)
	if cfg.UseCLI {
		log.Println("[DarkScan] WARNING: use_cli mode is deprecated, please use use_daemon instead")
		return NewCLIClient(cfg, cfg.CLIBinaryPath)
	}

	// Try daemon mode if enabled
	if cfg.UseDaemon {
		log.Println("[DarkScan] Attempting daemon connection...")

		client, err := tryDaemonConnection(cfg)
		if err == nil {
			log.Printf("[DarkScan] ✅ Connected to daemon (%s)", client.GetConnectionStatus().Mode)
			return client, nil
		}

		log.Printf("[DarkScan] ⚠️  Daemon connection failed: %v", err)

		// Check if fallback is allowed
		if !cfg.FallbackToLibrary {
			return nil, fmt.Errorf("darkscan: daemon connection failed and fallback disabled: %w", err)
		}

		log.Println("[DarkScan] Falling back to library mode...")
	}

	// Create library mode client
	client, err := NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("darkscan: failed to create library client: %w", err)
	}

	log.Println("[DarkScan] ✅ Using library mode")
	return client, nil
}

// tryDaemonConnection attempts to connect to the DarkScan daemon.
// It tries Unix socket first, then TCP fallback.
func tryDaemonConnection(cfg *Config) (DarkScanClient, error) {
	// Check if socket file exists (quick pre-check)
	socketPath := cfg.DaemonSocket
	if socketPath == "" {
		socketPath = "/tmp/darkscand.sock"
	}

	// Try Unix socket first
	if _, err := os.Stat(socketPath); err == nil {
		client, err := connectToUnixSocket(cfg, socketPath)
		if err == nil {
			return client, nil
		}
		log.Printf("[DarkScan] Unix socket connection failed: %v", err)
	} else {
		log.Printf("[DarkScan] Unix socket not found at %s", socketPath)
	}

	// Try TCP fallback
	tcpAddr := cfg.DaemonTCPAddr
	if tcpAddr == "" {
		tcpAddr = "127.0.0.1:8080"
	}

	client, err := connectToTCP(cfg, tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("both Unix socket and TCP connection failed: %w", err)
	}

	return client, nil
}

// connectToUnixSocket attempts Unix socket connection with timeout
func connectToUnixSocket(cfg *Config, socketPath string) (DarkScanClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Create daemon client with Unix socket transport
	client, err := NewDaemonClient(cfg, socketPath, "")
	if err != nil {
		return nil, err
	}

	// Test connection with ping
	if err := testConnection(ctx, client); err != nil {
		client.Close()
		return nil, fmt.Errorf("socket connection test failed: %w", err)
	}

	return client, nil
}

// connectToTCP attempts TCP connection with timeout
func connectToTCP(cfg *Config, tcpAddr string) (DarkScanClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Create daemon client with TCP transport
	client, err := NewDaemonClient(cfg, "", tcpAddr)
	if err != nil {
		return nil, err
	}

	// Test connection with ping
	if err := testConnection(ctx, client); err != nil {
		client.Close()
		return nil, fmt.Errorf("TCP connection test failed: %w", err)
	}

	return client, nil
}

// testConnection verifies the daemon is responsive
func testConnection(ctx context.Context, client DarkScanClient) error {
	// Get connection status (which pings the daemon)
	status := client.GetConnectionStatus()

	if !status.DaemonConnected {
		if status.LastError != "" {
			return fmt.Errorf("daemon not connected: %s", status.LastError)
		}
		return fmt.Errorf("daemon not connected")
	}

	return nil
}
