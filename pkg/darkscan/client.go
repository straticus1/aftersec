package darkscan

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	dscapa "github.com/afterdarksys/darkscan/pkg/capa"
	dsclamav "github.com/afterdarksys/darkscan/pkg/clamav"
	dsscanner "github.com/afterdarksys/darkscan/pkg/scanner"
	dsviper "github.com/afterdarksys/darkscan/pkg/viper"
	dsyara "github.com/afterdarksys/darkscan/pkg/yara"
)

type cacheEntry struct {
	Result    *ScanResult
	Timestamp time.Time
}

// Client wraps the DarkScan scanner with AfterSec-specific integration
type Client struct {
	scanner           *dsscanner.Scanner
	config            *Config
	cache             sync.Map
	hashStore         *HashStore
	fileTypeDetector  *FileTypeDetector
	profileManager    *ProfileManager
	privacyScanner    *PrivacyScanner
	ruleManager       *RuleManager
	quarantineManager *QuarantineManager
	stegoDetector     *StegoDetector
	containerScanner  *ContainerScanner
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

	// Initialize hash store
	if cfg.HashStore.Enabled {
		hashStore, err := NewHashStore(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize hash store: %w", err)
		}
		client.hashStore = hashStore
	}

	// Initialize file type detector
	if cfg.FileType.Enabled {
		fileTypeDetector, err := NewFileTypeDetector(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize file type detector: %w", err)
		}
		client.fileTypeDetector = fileTypeDetector
	}

	// Initialize profile manager
	if cfg.Profiles.Enabled {
		profileManager, err := NewProfileManager(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize profile manager: %w", err)
		}
		client.profileManager = profileManager
	}

	// Initialize privacy scanner
	if cfg.Privacy.Enabled {
		privacyScanner, err := NewPrivacyScanner(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize privacy scanner: %w", err)
		}
		client.privacyScanner = privacyScanner
	}

	// Initialize rule manager
	if cfg.RuleManager.Enabled {
		ruleManager, err := NewRuleManager(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize rule manager: %w", err)
		}
		client.ruleManager = ruleManager
	}

	// Initialize quarantine manager
	if cfg.Quarantine.Enabled {
		quarantineManager, err := NewQuarantineManager(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize quarantine manager: %w", err)
		}
		client.quarantineManager = quarantineManager
	}

	// Initialize steganography detector (always enabled for image analysis)
	stegoDetector, err := NewStegoDetector(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize steganography detector: %w", err)
	}
	client.stegoDetector = stegoDetector

	// Initialize container scanner (always enabled if tools available)
	containerScanner, err := NewContainerScanner(cfg, client)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize container scanner: %w", err)
	}
	client.containerScanner = containerScanner

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
	// File type validation (if enabled)
	if c.fileTypeDetector != nil && c.config.FileType.DetectSpoofing {
		if err := c.fileTypeDetector.ValidateBeforeScan(ctx, path, true); err != nil {
			return &ScanResult{
				FilePath: path,
				Error:    err,
			}, err
		}
	}

	// Hash store deduplication check (if enabled)
	if c.hashStore != nil && c.config.HashStore.DeduplicateScans {
		hash, err := CalculateFileHash(path)
		if err == nil {
			if entry, err := c.hashStore.CheckHash(ctx, hash); err == nil && entry != nil {
				// Check if entry is recent enough to skip rescan
				retentionDays := c.config.HashStore.RetentionDays
				if retentionDays == 0 {
					retentionDays = 90
				}
				if time.Since(entry.LastSeen) < time.Duration(retentionDays)*24*time.Hour {
					// Return cached result from hash store
					return &ScanResult{
						FilePath:    path,
						Infected:    entry.Infected,
						Threats:     entry.Threats,
						EngineCount: len(c.getEnabledEngines()),
					}, nil
				}
			}
		}
	}

	// Memory cache check (backward compatibility)
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

	// Perform actual scan
	results, err := c.scanner.ScanFile(ctx, path)
	if err != nil {
		return &ScanResult{
			FilePath: path,
			Error:    err,
		}, err
	}

	aggregated := c.aggregateResults(path, results)

	// Store in hash store
	if c.hashStore != nil {
		if err := c.hashStore.StoreResult(ctx, aggregated); err != nil {
			// Log error but don't fail the scan
			fmt.Fprintf(os.Stderr, "Warning: failed to store scan result in hash store: %v\n", err)
		}
	}

	// Memory cache (backward compatibility)
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
// Privacy Operations
//

func (c *Client) ScanBrowserPrivacy(ctx context.Context, browsers []string) ([]*PrivacyScanResult, error) {
	if c.privacyScanner == nil {
		return nil, fmt.Errorf("privacy scanner not enabled")
	}
	return c.privacyScanner.ScanBrowserPrivacy(ctx, browsers)
}

func (c *Client) ScanApplicationTelemetry(ctx context.Context, appPath string) (*PrivacyScanResult, error) {
	if c.privacyScanner == nil {
		return nil, fmt.Errorf("privacy scanner not enabled")
	}
	return c.privacyScanner.ScanApplicationTelemetry(ctx, appPath)
}

func (c *Client) ListPrivacyFindings(ctx context.Context, filters PrivacyFilter) ([]*PrivacyFinding, error) {
	if c.privacyScanner == nil {
		return nil, fmt.Errorf("privacy scanner not enabled")
	}
	return c.privacyScanner.ListPrivacyFindings(ctx, filters)
}

func (c *Client) RemoveTrackers(ctx context.Context, browser string, trackerIDs []string) error {
	if c.privacyScanner == nil {
		return fmt.Errorf("privacy scanner not enabled")
	}
	return c.privacyScanner.RemoveTrackers(ctx, browser, trackerIDs)
}

//
// Quarantine Operations
//

func (c *Client) QuarantineFile(ctx context.Context, source string, threats []Threat) (string, error) {
	if c.quarantineManager == nil {
		return "", fmt.Errorf("quarantine not enabled")
	}
	return c.quarantineManager.QuarantineFile(ctx, source, threats)
}

func (c *Client) ListQuarantine(ctx context.Context) ([]*QuarantineInfo, error) {
	if c.quarantineManager == nil {
		return nil, fmt.Errorf("quarantine not enabled")
	}
	return c.quarantineManager.ListQuarantine(ctx)
}

func (c *Client) GetQuarantineInfo(ctx context.Context, quarantineID string) (*QuarantineInfo, error) {
	if c.quarantineManager == nil {
		return nil, fmt.Errorf("quarantine not enabled")
	}
	return c.quarantineManager.GetQuarantineInfo(ctx, quarantineID)
}

func (c *Client) RestoreQuarantined(ctx context.Context, quarantineID string, destination string) error {
	if c.quarantineManager == nil {
		return fmt.Errorf("quarantine not enabled")
	}
	return c.quarantineManager.RestoreQuarantined(ctx, quarantineID, destination)
}

func (c *Client) DeleteQuarantined(ctx context.Context, quarantineID string) error {
	if c.quarantineManager == nil {
		return fmt.Errorf("quarantine not enabled")
	}
	return c.quarantineManager.DeleteQuarantined(ctx, quarantineID)
}

func (c *Client) CleanQuarantine(ctx context.Context, olderThan time.Duration) (int, error) {
	if c.quarantineManager == nil {
		return 0, fmt.Errorf("quarantine not enabled")
	}
	return c.quarantineManager.CleanQuarantine(ctx, olderThan)
}

//
// Rule Management Operations
//

func (c *Client) UpdateRules(ctx context.Context) error {
	if c.ruleManager == nil {
		return fmt.Errorf("rule manager not enabled")
	}
	return c.ruleManager.UpdateRules(ctx)
}

func (c *Client) ListRuleRepositories() ([]*RuleRepository, error) {
	if c.ruleManager == nil {
		return nil, fmt.Errorf("rule manager not enabled")
	}
	return c.ruleManager.ListRuleRepositories()
}

func (c *Client) AddRuleRepository(ctx context.Context, url, branch string) error {
	if c.ruleManager == nil {
		return fmt.Errorf("rule manager not enabled")
	}
	return c.ruleManager.AddRuleRepository(ctx, url, branch)
}

func (c *Client) RemoveRuleRepository(url string) error {
	if c.ruleManager == nil {
		return fmt.Errorf("rule manager not enabled")
	}
	return c.ruleManager.RemoveRuleRepository(url)
}

func (c *Client) GetRuleInfo() (*RuleInfo, error) {
	if c.ruleManager == nil {
		return nil, fmt.Errorf("rule manager not enabled")
	}
	return c.ruleManager.GetRuleInfo()
}

//
// Profile Operations
//

func (c *Client) ApplyProfile(profileName string) error {
	if c.profileManager == nil {
		return fmt.Errorf("profile manager not enabled")
	}
	profile, err := c.profileManager.ApplyProfile(profileName)
	if err != nil {
		return err
	}
	// Apply profile settings to config
	ApplyProfileToConfig(c.config, profile)
	// Reinitialize engines with new configuration
	return c.initializeEngines()
}

func (c *Client) ListProfiles() ([]*Profile, error) {
	if c.profileManager == nil {
		return nil, fmt.Errorf("profile manager not enabled")
	}
	return c.profileManager.ListProfiles()
}

func (c *Client) GetProfile(name string) (*Profile, error) {
	if c.profileManager == nil {
		return nil, fmt.Errorf("profile manager not enabled")
	}
	return c.profileManager.GetProfile(name)
}

func (c *Client) CreateCustomProfile(profile *Profile) error {
	if c.profileManager == nil {
		return fmt.Errorf("profile manager not enabled")
	}
	return c.profileManager.CreateCustomProfile(profile)
}

func (c *Client) DeleteCustomProfile(name string) error {
	if c.profileManager == nil {
		return fmt.Errorf("profile manager not enabled")
	}
	return c.profileManager.DeleteCustomProfile(name)
}

//
// File Type Operations
//

func (c *Client) IdentifyFileType(ctx context.Context, path string) (*FileTypeResult, error) {
	if c.fileTypeDetector == nil {
		return nil, fmt.Errorf("file type detector not enabled")
	}
	return c.fileTypeDetector.IdentifyFileType(ctx, path)
}

func (c *Client) VerifyExtension(ctx context.Context, path string) (bool, error) {
	if c.fileTypeDetector == nil {
		return false, fmt.Errorf("file type detector not enabled")
	}
	return c.fileTypeDetector.VerifyExtension(ctx, path)
}

func (c *Client) DetectSpoofing(ctx context.Context, path string, recursive bool) ([]*FileTypeResult, error) {
	if c.fileTypeDetector == nil {
		return nil, fmt.Errorf("file type detector not enabled")
	}
	return c.fileTypeDetector.DetectSpoofing(ctx, path, recursive)
}

//
// Hash Store Operations
//

func (c *Client) CheckHash(ctx context.Context, hash string) (*HashEntry, error) {
	if c.hashStore == nil {
		return nil, fmt.Errorf("hash store not enabled")
	}
	return c.hashStore.CheckHash(ctx, hash)
}

func (c *Client) StoreResult(ctx context.Context, result *ScanResult) error {
	if c.hashStore == nil {
		return fmt.Errorf("hash store not enabled")
	}
	return c.hashStore.StoreResult(ctx, result)
}

func (c *Client) GetScanHistory(ctx context.Context, filters HistoryFilter) ([]*HashEntry, error) {
	if c.hashStore == nil {
		return nil, fmt.Errorf("hash store not enabled")
	}
	return c.hashStore.GetScanHistory(ctx, filters)
}

func (c *Client) SearchHistory(ctx context.Context, query string) ([]*HashEntry, error) {
	if c.hashStore == nil {
		return nil, fmt.Errorf("hash store not enabled")
	}
	return c.hashStore.SearchHistory(ctx, query)
}

func (c *Client) PruneHashStore(ctx context.Context, olderThan time.Duration) (int, error) {
	if c.hashStore == nil {
		return 0, fmt.Errorf("hash store not enabled")
	}
	return c.hashStore.PruneHashStore(ctx, olderThan)
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

//
// Steganography Operations
//

func (c *Client) DetectSteganography(ctx context.Context, path string) (*StegoResult, error) {
	if c.stegoDetector == nil {
		return nil, fmt.Errorf("steganography detector not initialized")
	}
	return c.stegoDetector.DetectSteganography(ctx, path)
}

func (c *Client) BatchDetectSteganography(ctx context.Context, paths []string) ([]*StegoResult, error) {
	if c.stegoDetector == nil {
		return nil, fmt.Errorf("steganography detector not initialized")
	}
	return c.stegoDetector.BatchDetectSteganography(ctx, paths)
}

//
// Container Image Scanning Operations
//

func (c *Client) ScanContainerImage(ctx context.Context, imageRef string) (*ContainerScanResult, error) {
	if c.containerScanner == nil {
		return nil, fmt.Errorf("container scanner not initialized")
	}
	return c.containerScanner.ScanImage(ctx, imageRef)
}

// Close releases all engine resources
func (c *Client) Close() error {
	if c.quarantineManager != nil {
		if err := c.quarantineManager.Close(); err != nil {
			return fmt.Errorf("failed to close quarantine manager: %w", err)
		}
	}
	if c.hashStore != nil {
		if err := c.hashStore.Close(); err != nil {
			return fmt.Errorf("failed to close hash store: %w", err)
		}
	}
	return c.scanner.Close()
}
