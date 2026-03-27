package darkscan

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	dscapa "github.com/afterdarktech/darkscan/pkg/capa"
	dsclamav "github.com/afterdarktech/darkscan/pkg/clamav"
	dsscanner "github.com/afterdarktech/darkscan/pkg/scanner"
	dsviper "github.com/afterdarktech/darkscan/pkg/viper"
	dsyara "github.com/afterdarktech/darkscan/pkg/yara"
)

type cacheEntry struct {
	Result    *ScanResult
	Timestamp time.Time
}

// Client wraps the DarkScan scanner with AfterSec-specific integration
type Client struct {
	scanner *dsscanner.Scanner
	config  *Config
	cache   sync.Map
}

// ScanResult represents unified scan results from DarkScan
type ScanResult struct {
	FilePath     string
	Infected     bool
	Threats      []Threat
	EngineCount  int
	EnginesUsed  []string
	ScanDuration time.Duration
	Error        error
}

// Threat represents a detected threat
type Threat struct {
	Name        string
	Severity    string
	Description string
	Engine      string
}

// NewClient creates a new DarkScan client with the given configuration
func NewClient(cfg *Config) (*Client, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	scanner := dsscanner.New()
	client := &Client{
		scanner: scanner,
		config:  cfg,
	}

	// Initialize and register enabled engines
	if err := client.initializeEngines(); err != nil {
		return nil, fmt.Errorf("failed to initialize DarkScan engines: %w", err)
	}

	return client, nil
}

// initializeEngines registers all enabled scanning engines
func (c *Client) initializeEngines() error {
	var errors []error

	// ClamAV Engine
	if c.config.Engines.ClamAV.Enabled {
		if _, err := os.Stat(c.config.Engines.ClamAV.DatabasePath); os.IsNotExist(err) {
			errors = append(errors, fmt.Errorf("ClamAV: database path does not exist: %s", c.config.Engines.ClamAV.DatabasePath))
		} else {
			engine, err := dsclamav.New(c.config.Engines.ClamAV.DatabasePath)
			if err != nil {
				errors = append(errors, fmt.Errorf("ClamAV initialization failed: %w", err))
			} else {
				c.scanner.RegisterEngine(engine)
			}
		}
	}

	// YARA Engine
	if c.config.Engines.YARA.Enabled {
		if c.config.Engines.YARA.RulesPath == "" {
			errors = append(errors, fmt.Errorf("YARA: rules path is required when YARA is enabled"))
		} else if _, err := os.Stat(c.config.Engines.YARA.RulesPath); os.IsNotExist(err) {
			errors = append(errors, fmt.Errorf("YARA: rules path does not exist: %s", c.config.Engines.YARA.RulesPath))
		} else {
			engine, err := dsyara.New(c.config.Engines.YARA.RulesPath)
			if err != nil {
				errors = append(errors, fmt.Errorf("YARA initialization failed: %w", err))
			} else {
				c.scanner.RegisterEngine(engine)
			}
		}
	}

	// CAPA Engine
	if c.config.Engines.CAPA.Enabled {
		engine, err := dscapa.New(c.config.Engines.CAPA.ExePath, c.config.Engines.CAPA.RulesPath)
		if err != nil {
			errors = append(errors, fmt.Errorf("CAPA initialization failed: %w", err))
		} else {
			c.scanner.RegisterEngine(engine)
		}
	}

	// Viper Engine
	if c.config.Engines.Viper.Enabled {
		engine, err := dsviper.New(c.config.Engines.Viper.ExePath)
		if err != nil {
			errors = append(errors, fmt.Errorf("Viper initialization failed: %w", err))
		} else {
			if c.config.Engines.Viper.ProjectName != "" {
				engine.SetProject(c.config.Engines.Viper.ProjectName)
			}
			c.scanner.RegisterEngine(engine)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("engine initialization errors: %v", errors)
	}

	return nil
}

// ScanFile scans a single file with all enabled engines
func (c *Client) ScanFile(ctx context.Context, path string) (*ScanResult, error) {
	if c.config.CacheEnabled {
		if info, err := os.Stat(path); err == nil {
			cacheKey := path + "_" + info.ModTime().String()
			if val, ok := c.cache.Load(cacheKey); ok {
				entry := val.(cacheEntry)
				ttl, parseErr := time.ParseDuration(c.config.CacheTTL)
				if parseErr != nil || ttl == 0 {
					ttl = 24 * time.Hour
				}
				if time.Since(entry.Timestamp) < ttl {
					return entry.Result, nil
				}
				c.cache.Delete(cacheKey)
			}
		}
	}

	results, err := c.scanner.ScanFile(ctx, path)
	if err != nil {
		return &ScanResult{
			FilePath: path,
			Error:    err,
		}, err
	}

	aggregated := c.aggregateResults(path, results)

	if c.config.CacheEnabled {
		if info, err := os.Stat(path); err == nil {
			cacheKey := path + "_" + info.ModTime().String()
			c.cache.Store(cacheKey, cacheEntry{
				Result:    aggregated,
				Timestamp: time.Now(),
			})
		}
	}

	return aggregated, nil
}

// ScanDirectory scans a directory recursively with all enabled engines
func (c *Client) ScanDirectory(ctx context.Context, path string, recursive bool) ([]*ScanResult, error) {
	results, err := c.scanner.ScanDirectory(ctx, path, recursive)
	if err != nil {
		return nil, err
	}

	aggregated := make(map[string]*ScanResult)
	for _, result := range results {
		if existing, ok := aggregated[result.FilePath]; ok {
			c.mergeResults(existing, result)
		} else {
			aggregated[result.FilePath] = c.convertResult(result)
		}
	}

	var finalResults []*ScanResult
	for _, result := range aggregated {
		finalResults = append(finalResults, result)
	}

	return finalResults, nil
}

// QuickScan performs a fast scan optimized for real-time detection
func (c *Client) QuickScan(ctx context.Context, path string) (bool, error) {
	result, err := c.ScanFile(ctx, path)
	if err != nil {
		return false, err
	}
	return result.Infected, nil
}

// aggregateResults combines results from multiple engines for a single file
func (c *Client) aggregateResults(path string, dsResults []*dsscanner.ScanResult) *ScanResult {
	result := &ScanResult{
		FilePath:    path,
		Infected:    false,
		Threats:     []Threat{},
		EngineCount: len(dsResults),
	}

	for _, dsResult := range dsResults {
		if dsResult.Error != nil {
			result.Error = dsResult.Error
			continue
		}

		if dsResult.Infected {
			result.Infected = true
			for _, threat := range dsResult.Threats {
				result.Threats = append(result.Threats, Threat{
					Name:        threat.Name,
					Severity:    threat.Severity,
					Description: threat.Description,
					Engine:      dsResult.ScanEngine,
				})
			}
		}
	}

	return result
}

// convertResult converts DarkScan result to AfterSec result
func (c *Client) convertResult(dsResult *dsscanner.ScanResult) *ScanResult {
	result := &ScanResult{
		FilePath:    dsResult.FilePath,
		Infected:    dsResult.Infected,
		Threats:     []Threat{},
		EngineCount: 1,
		Error:       dsResult.Error,
	}

	for _, threat := range dsResult.Threats {
		result.Threats = append(result.Threats, Threat{
			Name:        threat.Name,
			Severity:    threat.Severity,
			Description: threat.Description,
			Engine:      dsResult.ScanEngine,
		})
	}

	return result
}

// mergeResults merges a new result into an existing result
func (c *Client) mergeResults(existing *ScanResult, dsResult *dsscanner.ScanResult) {
	existing.EngineCount++

	if dsResult.Infected {
		existing.Infected = true
		for _, threat := range dsResult.Threats {
			existing.Threats = append(existing.Threats, Threat{
				Name:        threat.Name,
				Severity:    threat.Severity,
				Description: threat.Description,
				Engine:      dsResult.ScanEngine,
			})
		}
	}

	if dsResult.Error != nil {
		existing.Error = dsResult.Error
	}
}

// UpdateEngines updates all virus definitions and rules
func (c *Client) UpdateEngines(ctx context.Context) error {
	return c.scanner.UpdateEngines(ctx)
}

//
// Privacy Operations - Stubs for Phase 3
//

func (c *Client) ScanBrowserPrivacy(ctx context.Context, browsers []string) ([]*PrivacyScanResult, error) {
	return nil, fmt.Errorf("privacy scanning not yet implemented for library mode")
}

func (c *Client) ScanApplicationTelemetry(ctx context.Context, appPath string) (*PrivacyScanResult, error) {
	return nil, fmt.Errorf("telemetry scanning not yet implemented for library mode")
}

func (c *Client) ListPrivacyFindings(ctx context.Context, filters PrivacyFilter) ([]*PrivacyFinding, error) {
	return nil, fmt.Errorf("privacy findings not yet implemented for library mode")
}

func (c *Client) RemoveTrackers(ctx context.Context, browser string, trackerIDs []string) error {
	return fmt.Errorf("tracker removal not yet implemented for library mode")
}

//
// Quarantine Operations - Stubs for Phase 4
//

func (c *Client) QuarantineFile(ctx context.Context, source string, threats []Threat) (string, error) {
	return "", fmt.Errorf("quarantine not yet implemented for library mode")
}

func (c *Client) ListQuarantine(ctx context.Context) ([]*QuarantineInfo, error) {
	return nil, fmt.Errorf("quarantine listing not yet implemented for library mode")
}

func (c *Client) GetQuarantineInfo(ctx context.Context, quarantineID string) (*QuarantineInfo, error) {
	return nil, fmt.Errorf("quarantine info not yet implemented for library mode")
}

func (c *Client) RestoreQuarantined(ctx context.Context, quarantineID string, destination string) error {
	return fmt.Errorf("quarantine restore not yet implemented for library mode")
}

func (c *Client) DeleteQuarantined(ctx context.Context, quarantineID string) error {
	return fmt.Errorf("quarantine delete not yet implemented for library mode")
}

func (c *Client) CleanQuarantine(ctx context.Context, olderThan time.Duration) (int, error) {
	return 0, fmt.Errorf("quarantine cleanup not yet implemented for library mode")
}

//
// Rule Management Operations - Stubs for Phase 3
//

func (c *Client) UpdateRules(ctx context.Context) error {
	return fmt.Errorf("rule updates not yet implemented for library mode")
}

func (c *Client) ListRuleRepositories() ([]*RuleRepository, error) {
	return nil, fmt.Errorf("rule repository listing not yet implemented for library mode")
}

func (c *Client) AddRuleRepository(ctx context.Context, url, branch string) error {
	return fmt.Errorf("adding rule repositories not yet implemented for library mode")
}

func (c *Client) RemoveRuleRepository(url string) error {
	return fmt.Errorf("removing rule repositories not yet implemented for library mode")
}

func (c *Client) GetRuleInfo() (*RuleInfo, error) {
	return nil, fmt.Errorf("rule info not yet implemented for library mode")
}

//
// Profile Operations - Stubs for Phase 2
//

func (c *Client) ApplyProfile(profileName string) error {
	return fmt.Errorf("profiles not yet implemented for library mode")
}

func (c *Client) ListProfiles() ([]*Profile, error) {
	return nil, fmt.Errorf("profiles not yet implemented for library mode")
}

func (c *Client) GetProfile(name string) (*Profile, error) {
	return nil, fmt.Errorf("profiles not yet implemented for library mode")
}

func (c *Client) CreateCustomProfile(profile *Profile) error {
	return fmt.Errorf("custom profiles not yet implemented for library mode")
}

func (c *Client) DeleteCustomProfile(name string) error {
	return fmt.Errorf("deleting profiles not yet implemented for library mode")
}

//
// File Type Operations - Stubs for Phase 2
//

func (c *Client) IdentifyFileType(ctx context.Context, path string) (*FileTypeResult, error) {
	return nil, fmt.Errorf("file type identification not yet implemented for library mode")
}

func (c *Client) VerifyExtension(ctx context.Context, path string) (bool, error) {
	return false, fmt.Errorf("extension verification not yet implemented for library mode")
}

func (c *Client) DetectSpoofing(ctx context.Context, path string, recursive bool) ([]*FileTypeResult, error) {
	return nil, fmt.Errorf("spoofing detection not yet implemented for library mode")
}

//
// Hash Store Operations - Stubs for Phase 2
//

func (c *Client) CheckHash(ctx context.Context, hash string) (*HashEntry, error) {
	return nil, fmt.Errorf("hash checking not yet implemented for library mode")
}

func (c *Client) StoreResult(ctx context.Context, result *ScanResult) error {
	return fmt.Errorf("result storage not yet implemented for library mode")
}

func (c *Client) GetScanHistory(ctx context.Context, filters HistoryFilter) ([]*HashEntry, error) {
	return nil, fmt.Errorf("scan history not yet implemented for library mode")
}

func (c *Client) SearchHistory(ctx context.Context, query string) ([]*HashEntry, error) {
	return nil, fmt.Errorf("history search not yet implemented for library mode")
}

func (c *Client) PruneHashStore(ctx context.Context, olderThan time.Duration) (int, error) {
	return 0, fmt.Errorf("hash store pruning not yet implemented for library mode")
}

//
// Engine Management Operations
//

func (c *Client) GetEnabledEngines() []string {
	// Return list of enabled engine names
	var engines []string

	if c.config.Engines.ClamAV.Enabled {
		engines = append(engines, "ClamAV")
	}
	if c.config.Engines.YARA.Enabled {
		engines = append(engines, "YARA")
	}
	if c.config.Engines.CAPA.Enabled {
		engines = append(engines, "CAPA")
	}
	if c.config.Engines.Viper.Enabled {
		engines = append(engines, "Viper")
	}
	if c.config.Engines.Document.Enabled {
		engines = append(engines, "Document")
	}
	if c.config.Engines.Heuristics.Enabled {
		engines = append(engines, "Heuristics")
	}
	if c.config.Engines.VirusTotal.Enabled {
		engines = append(engines, "VirusTotal")
	}

	return engines
}

func (c *Client) GetEngineCount() int {
	return len(c.GetEnabledEngines())
}

func (c *Client) IsEnabled() bool {
	return c.config.Enabled
}

//
// Connection Management
//

func (c *Client) GetConnectionStatus() ConnectionStatus {
	return ConnectionStatus{
		Mode:            "library",
		DaemonConnected: false,
		SocketPath:      "",
		TCPAddress:      "",
		LastError:       "",
		LastChecked:     time.Now(),
		Uptime:          "",
	}
}

// Close releases all engine resources
func (c *Client) Close() error {
	return c.scanner.Close()
}
