package darkscan

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	dsclient "github.com/afterdarksys/darkscan/pkg/api/client"
	dsscanner "github.com/afterdarksys/darkscan/pkg/scanner"
)

// DaemonClient implements DarkScanClient by connecting to the DarkScan daemon.
// It wraps the DarkScan API client and provides high-level operations.
type DaemonClient struct {
	config      *Config
	apiClient   *dsclient.Client
	socketPath  string
	tcpAddr     string
	isConnected bool
	lastError   string
	lastChecked time.Time
	mu          sync.RWMutex
}

// NewDaemonClient creates a new daemon client.
// Provide either socketPath (Unix socket) or tcpAddr (TCP), not both.
func NewDaemonClient(cfg *Config, socketPath, tcpAddr string) (*DaemonClient, error) {
	if socketPath == "" && tcpAddr == "" {
		return nil, fmt.Errorf("either socketPath or tcpAddr must be provided")
	}

	// Determine base URL based on transport
	var baseURL string
	if socketPath != "" {
		// Unix socket uses special HTTP transport
		baseURL = "http://unix"
	} else {
		baseURL = fmt.Sprintf("http://%s", tcpAddr)
	}

	// Create DarkScan API client
	// Note: DarkScan's client library handles Unix socket transport internally
	apiClient, err := dsclient.NewClient(
		baseURL,
		socketPath,
		time.Minute,  // request timeout
		2*time.Second, // connect timeout
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}

	client := &DaemonClient{
		config:      cfg,
		apiClient:   apiClient,
		socketPath:  socketPath,
		tcpAddr:     tcpAddr,
		isConnected: false,
		lastChecked: time.Now(),
	}

	// Test connection
	if err := client.ping(context.Background()); err != nil {
		return nil, fmt.Errorf("initial connection test failed: %w", err)
	}

	client.isConnected = true
	return client, nil
}

// ping tests daemon connectivity
func (d *DaemonClient) ping(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	status, err := d.apiClient.GetStatus()
	if err != nil {
		d.isConnected = false
		d.lastError = err.Error()
		d.lastChecked = time.Now()
		return err
	}

	if status.Status != "running" {
		err := fmt.Errorf("daemon status: %s", status.Status)
		d.isConnected = false
		d.lastError = err.Error()
		return err
	}

	d.isConnected = true
	d.lastError = ""
	d.lastChecked = time.Now()
	return nil
}

// tryReconnect attempts to reconnect to the daemon
func (d *DaemonClient) tryReconnect(ctx context.Context) error {
	return d.ping(ctx)
}

// StartConnectionMonitor starts a background goroutine that periodically
// checks daemon health and attempts reconnection if disconnected.
func (d *DaemonClient) StartConnectionMonitor(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 5 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.mu.RLock()
				connected := d.isConnected
				d.mu.RUnlock()

				if !connected {
					if err := d.tryReconnect(ctx); err == nil {
						log.Printf("✅ [DarkScan] Reconnected to daemon")
					}
				} else {
					// Periodic health check
					_ = d.ping(ctx)
				}
			}
		}
	}()
}

//
// DarkScanClient interface implementation
//

// ScanFile scans a single file using the daemon
func (d *DaemonClient) ScanFile(ctx context.Context, path string) (*ScanResult, error) {
	d.mu.RLock()
	if !d.isConnected {
		d.mu.RUnlock()
		return nil, fmt.Errorf("daemon not connected: %s", d.lastError)
	}
	d.mu.RUnlock()

	// Use DarkScan API client's ScanLocal method
	dsResults, err := d.apiClient.ScanLocal(path, false)
	if err != nil {
		return nil, fmt.Errorf("daemon scan failed: %w", err)
	}

	// Convert DarkScan results to AfterSec format
	result := d.convertScanResults(path, dsResults)
	return result, nil
}

// ScanDirectory scans a directory using the daemon
func (d *DaemonClient) ScanDirectory(ctx context.Context, path string, recursive bool) ([]*ScanResult, error) {
	d.mu.RLock()
	if !d.isConnected {
		d.mu.RUnlock()
		return nil, fmt.Errorf("daemon not connected: %s", d.lastError)
	}
	d.mu.RUnlock()

	// Use DarkScan API client's ScanLocal method with recursive flag
	dsResults, err := d.apiClient.ScanLocal(path, recursive)
	if err != nil {
		return nil, fmt.Errorf("daemon scan failed: %w", err)
	}

	// Convert all results
	var results []*ScanResult
	for _, dsResult := range dsResults {
		result := d.convertScanResults(dsResult.FilePath, []*dsscanner.ScanResult{dsResult})
		results = append(results, result)
	}

	return results, nil
}

// ScanWithReport performs a scan and returns detailed report
func (d *DaemonClient) ScanWithReport(ctx context.Context, path string) (*IntegrationReport, error) {
	result, err := d.ScanFile(ctx, path)
	if err != nil {
		return nil, err
	}

	// Build integration report
	report := &IntegrationReport{
		FilePath:     path,
		Scanned:      true,
		Infected:     result.Infected,
		ThreatLevel:  CalculateThreatLevel(result),
		Threats:      result.Threats,
		Engines:      result.EnginesUsed,
		ScanDuration: result.ScanDuration,
		Error:        nil,
	}

	return report, nil
}

// QuickScan performs fast boolean check
func (d *DaemonClient) QuickScan(ctx context.Context, path string) (bool, error) {
	result, err := d.ScanFile(ctx, path)
	if err != nil {
		return false, err
	}
	return result.Infected, nil
}

// RealTimeScan performs time-limited scan for EDR
func (d *DaemonClient) RealTimeScan(ctx context.Context, path string, timeoutSeconds int) (bool, ThreatLevel, error) {
	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	result, err := d.ScanFile(scanCtx, path)
	if err != nil {
		// Timeout or error - default to allow for fail-open security
		return false, ThreatLevelNone, err
	}

	threatLevel := CalculateThreatLevel(result)
	shouldBlock := threatLevel >= ThreatLevelHigh

	return shouldBlock, threatLevel, nil
}

// convertScanResults converts DarkScan API results to AfterSec format
func (d *DaemonClient) convertScanResults(path string, dsResults []*dsscanner.ScanResult) *ScanResult {
	result := &ScanResult{
		FilePath:  path,
		Infected:  false,
		Threats:   []Threat{},
		EnginesUsed: []string{},
	}

	for _, dsResult := range dsResults {
		if dsResult.Infected {
			result.Infected = true
			result.EnginesUsed = append(result.EnginesUsed, dsResult.ScanEngine)

			// Add threats from DarkScan results
			for _, dsThreat := range dsResult.Threats {
				threat := Threat{
					Name:        dsThreat.Name,
					Engine:      dsResult.ScanEngine,
					Severity:    dsThreat.Severity,
					Description: dsThreat.Description,
				}
				result.Threats = append(result.Threats, threat)
			}
		}
	}

	return result
}

//
// Placeholder implementations for advanced features (Phase 2-4)
// These will be fully implemented in later phases
//

func (d *DaemonClient) ScanBrowserPrivacy(ctx context.Context, browsers []string) ([]*PrivacyScanResult, error) {
	return nil, fmt.Errorf("privacy scanning not yet implemented for daemon mode")
}

func (d *DaemonClient) ScanApplicationTelemetry(ctx context.Context, appPath string) (*PrivacyScanResult, error) {
	return nil, fmt.Errorf("telemetry scanning not yet implemented for daemon mode")
}

func (d *DaemonClient) ListPrivacyFindings(ctx context.Context, filters PrivacyFilter) ([]*PrivacyFinding, error) {
	return nil, fmt.Errorf("privacy findings not yet implemented for daemon mode")
}

func (d *DaemonClient) RemoveTrackers(ctx context.Context, browser string, trackerIDs []string) error {
	return fmt.Errorf("tracker removal not yet implemented for daemon mode")
}

func (d *DaemonClient) QuarantineFile(ctx context.Context, source string, threats []Threat) (string, error) {
	return "", fmt.Errorf("quarantine not yet implemented for daemon mode")
}

func (d *DaemonClient) ListQuarantine(ctx context.Context) ([]*QuarantineInfo, error) {
	return nil, fmt.Errorf("quarantine listing not yet implemented for daemon mode")
}

func (d *DaemonClient) GetQuarantineInfo(ctx context.Context, quarantineID string) (*QuarantineInfo, error) {
	return nil, fmt.Errorf("quarantine info not yet implemented for daemon mode")
}

func (d *DaemonClient) RestoreQuarantined(ctx context.Context, quarantineID string, destination string) error {
	return fmt.Errorf("quarantine restore not yet implemented for daemon mode")
}

func (d *DaemonClient) DeleteQuarantined(ctx context.Context, quarantineID string) error {
	return fmt.Errorf("quarantine delete not yet implemented for daemon mode")
}

func (d *DaemonClient) CleanQuarantine(ctx context.Context, olderThan time.Duration) (int, error) {
	return 0, fmt.Errorf("quarantine cleanup not yet implemented for daemon mode")
}

func (d *DaemonClient) UpdateRules(ctx context.Context) error {
	// Trigger daemon rule update via API
	return d.apiClient.TriggerUpdate()
}

func (d *DaemonClient) ListRuleRepositories() ([]*RuleRepository, error) {
	return nil, fmt.Errorf("rule repository listing not yet implemented for daemon mode")
}

func (d *DaemonClient) AddRuleRepository(ctx context.Context, url, branch string) error {
	return fmt.Errorf("adding rule repositories not yet implemented for daemon mode")
}

func (d *DaemonClient) RemoveRuleRepository(url string) error {
	return fmt.Errorf("removing rule repositories not yet implemented for daemon mode")
}

func (d *DaemonClient) GetRuleInfo() (*RuleInfo, error) {
	return nil, fmt.Errorf("rule info not yet implemented for daemon mode")
}

func (d *DaemonClient) ApplyProfile(profileName string) error {
	return fmt.Errorf("profiles not yet implemented for daemon mode")
}

func (d *DaemonClient) ListProfiles() ([]*Profile, error) {
	return nil, fmt.Errorf("profiles not yet implemented for daemon mode")
}

func (d *DaemonClient) GetProfile(name string) (*Profile, error) {
	return nil, fmt.Errorf("profiles not yet implemented for daemon mode")
}

func (d *DaemonClient) CreateCustomProfile(profile *Profile) error {
	return fmt.Errorf("custom profiles not yet implemented for daemon mode")
}

func (d *DaemonClient) DeleteCustomProfile(name string) error {
	return fmt.Errorf("deleting profiles not yet implemented for daemon mode")
}

func (d *DaemonClient) IdentifyFileType(ctx context.Context, path string) (*FileTypeResult, error) {
	return nil, fmt.Errorf("file type identification not yet implemented for daemon mode")
}

func (d *DaemonClient) VerifyExtension(ctx context.Context, path string) (bool, error) {
	return false, fmt.Errorf("extension verification not yet implemented for daemon mode")
}

func (d *DaemonClient) DetectSpoofing(ctx context.Context, path string, recursive bool) ([]*FileTypeResult, error) {
	return nil, fmt.Errorf("spoofing detection not yet implemented for daemon mode")
}

func (d *DaemonClient) DetectSteganography(ctx context.Context, path string) (*StegoResult, error) {
	return nil, fmt.Errorf("steganography detection not yet implemented for daemon mode")
}

func (d *DaemonClient) BatchDetectSteganography(ctx context.Context, paths []string) ([]*StegoResult, error) {
	return nil, fmt.Errorf("batch steganography detection not yet implemented for daemon mode")
}

func (d *DaemonClient) ScanContainerImage(ctx context.Context, imageRef string) (*ContainerScanResult, error) {
	return nil, fmt.Errorf("container image scanning not yet implemented for daemon mode")
}

func (d *DaemonClient) CheckHash(ctx context.Context, hash string) (*HashEntry, error) {
	return nil, fmt.Errorf("hash checking not yet implemented for daemon mode")
}

func (d *DaemonClient) StoreResult(ctx context.Context, result *ScanResult) error {
	return fmt.Errorf("result storage not yet implemented for daemon mode")
}

func (d *DaemonClient) GetScanHistory(ctx context.Context, filters HistoryFilter) ([]*HashEntry, error) {
	return nil, fmt.Errorf("scan history not yet implemented for daemon mode")
}

func (d *DaemonClient) SearchHistory(ctx context.Context, query string) ([]*HashEntry, error) {
	return nil, fmt.Errorf("history search not yet implemented for daemon mode")
}

func (d *DaemonClient) PruneHashStore(ctx context.Context, olderThan time.Duration) (int, error) {
	return 0, fmt.Errorf("hash store pruning not yet implemented for daemon mode")
}

func (d *DaemonClient) UpdateEngines(ctx context.Context) error {
	return d.apiClient.TriggerUpdate()
}

func (d *DaemonClient) GetEnabledEngines() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if !d.isConnected {
		return []string{}
	}

	// Query daemon status to get engine list
	status, err := d.apiClient.GetStatus()
	if err != nil {
		return []string{}
	}

	var engines []string
	for _, engine := range status.Engines {
		engines = append(engines, engine.Name)
	}
	return engines
}

func (d *DaemonClient) GetEngineCount() int {
	engines := d.GetEnabledEngines()
	return len(engines)
}

func (d *DaemonClient) IsEnabled() bool {
	return d.config.Enabled
}

func (d *DaemonClient) GetConnectionStatus() ConnectionStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	mode := "daemon"
	if d.socketPath != "" {
		mode = "daemon (unix socket)"
	} else if d.tcpAddr != "" {
		mode = "daemon (tcp)"
	}

	status := ConnectionStatus{
		Mode:            mode,
		DaemonConnected: d.isConnected,
		SocketPath:      d.socketPath,
		TCPAddress:      d.tcpAddr,
		LastError:       d.lastError,
		LastChecked:     d.lastChecked,
	}

	// Try to get daemon uptime if connected
	if d.isConnected {
		if daemonStatus, err := d.apiClient.GetStatus(); err == nil {
			status.Uptime = daemonStatus.Uptime
		}
	}

	return status
}

func (d *DaemonClient) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.isConnected = false
	// API client doesn't need explicit closing
	return nil
}
