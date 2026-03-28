package darkscan

import (
	"context"
	"time"
)

// DarkScanClient is the unified interface for all DarkScan operations.
// It abstracts both daemon and library mode implementations, allowing
// transparent switching between connection types.
type DarkScanClient interface {
	// Scanning Operations

	// ScanFile scans a single file for malware using configured engines.
	// Returns detailed scan results including threats found, engine verdicts, and metadata.
	ScanFile(ctx context.Context, path string) (*ScanResult, error)

	// ScanDirectory recursively scans a directory for malware.
	// Returns results for all scanned files.
	ScanDirectory(ctx context.Context, path string, recursive bool) ([]*ScanResult, error)

	// ScanWithReport performs a comprehensive scan with detailed threat analysis.
	// Includes threat severity levels and formatted reporting.
	ScanWithReport(ctx context.Context, path string) (*IntegrationReport, error)

	// QuickScan performs a fast boolean infection check.
	// Returns true if infected, false otherwise. No detailed threat info.
	QuickScan(ctx context.Context, path string) (bool, error)

	// RealTimeScan performs time-limited scanning for EDR real-time protection.
	// Returns shouldBlock, threatLevel, and error.
	RealTimeScan(ctx context.Context, path string, timeoutSeconds int) (bool, ThreatLevel, error)

	// Privacy Operations

	// ScanBrowserPrivacy scans specified browsers for tracking cookies,
	// suspicious extensions, and privacy violations.
	ScanBrowserPrivacy(ctx context.Context, browsers []string) ([]*PrivacyScanResult, error)

	// ScanApplicationTelemetry scans an application for telemetry endpoints
	// and data collection mechanisms.
	ScanApplicationTelemetry(ctx context.Context, appPath string) (*PrivacyScanResult, error)

	// ListPrivacyFindings retrieves previously detected privacy issues
	// filtered by browser, risk level, or other criteria.
	ListPrivacyFindings(ctx context.Context, filters PrivacyFilter) ([]*PrivacyFinding, error)

	// RemoveTrackers deletes specified tracking cookies and mechanisms
	// from a browser profile.
	RemoveTrackers(ctx context.Context, browser string, trackerIDs []string) error

	// Quarantine Operations

	// QuarantineFile isolates a file by moving it to quarantine storage
	// with optional encryption and metadata preservation.
	QuarantineFile(ctx context.Context, source string, threats []Threat) (string, error)

	// ListQuarantine retrieves all files currently in quarantine
	// with their metadata and threat information.
	ListQuarantine(ctx context.Context) ([]*QuarantineInfo, error)

	// GetQuarantineInfo retrieves detailed metadata for a specific
	// quarantined file by its quarantine ID.
	GetQuarantineInfo(ctx context.Context, quarantineID string) (*QuarantineInfo, error)

	// RestoreQuarantined moves a file out of quarantine back to its
	// original location or a specified destination.
	RestoreQuarantined(ctx context.Context, quarantineID string, destination string) error

	// DeleteQuarantined permanently removes a file from quarantine.
	// This operation cannot be undone.
	DeleteQuarantined(ctx context.Context, quarantineID string) error

	// CleanQuarantine removes quarantined files older than the specified duration.
	// Returns the number of files deleted.
	CleanQuarantine(ctx context.Context, olderThan time.Duration) (int, error)

	// Rule Management Operations

	// UpdateRules downloads and installs the latest YARA rules from
	// all configured repositories.
	UpdateRules(ctx context.Context) error

	// ListRuleRepositories retrieves information about configured
	// YARA rule sources (GitHub repos, custom locations).
	ListRuleRepositories() ([]*RuleRepository, error)

	// AddRuleRepository adds a new YARA rule source to the configuration.
	AddRuleRepository(ctx context.Context, url, branch string) error

	// RemoveRuleRepository removes a YARA rule source from the configuration.
	RemoveRuleRepository(url string) error

	// GetRuleInfo retrieves statistics about installed YARA rules
	// (count, last update time, sources).
	GetRuleInfo() (*RuleInfo, error)

	// Profile Operations

	// ApplyProfile configures the scanner with a named profile
	// (quick, standard, deep, forensic, safe, or custom).
	ApplyProfile(profileName string) error

	// ListProfiles retrieves all available scan profiles
	// (built-in and custom).
	ListProfiles() ([]*Profile, error)

	// GetProfile retrieves detailed information about a specific profile.
	GetProfile(name string) (*Profile, error)

	// CreateCustomProfile saves a new user-defined scan profile.
	CreateCustomProfile(profile *Profile) error

	// DeleteCustomProfile removes a user-defined profile.
	// Built-in profiles cannot be deleted.
	DeleteCustomProfile(name string) error

	// File Type Operations

	// IdentifyFileType analyzes a file's magic bytes to determine
	// its true type, regardless of extension.
	IdentifyFileType(ctx context.Context, path string) (*FileTypeResult, error)

	// VerifyExtension checks if a file's extension matches its actual content.
	// Returns false if the file is spoofed.
	VerifyExtension(ctx context.Context, path string) (bool, error)

	// DetectSpoofing scans a directory for files with mismatched
	// extensions and content types.
	DetectSpoofing(ctx context.Context, path string, recursive bool) ([]*FileTypeResult, error)

	// Steganography Operations

	// DetectSteganography analyzes an image for hidden data using
	// LSB analysis, DCT coefficient analysis, and statistical methods.
	DetectSteganography(ctx context.Context, path string) (*StegoResult, error)

	// BatchDetectSteganography scans multiple images for steganography.
	BatchDetectSteganography(ctx context.Context, paths []string) ([]*StegoResult, error)

	// Container Image Scanning Operations

	// ScanContainerImage performs comprehensive security scanning of
	// Docker/OCI container images including vulnerability scanning,
	// malware detection in layers, secret detection, and config analysis.
	ScanContainerImage(ctx context.Context, imageRef string) (*ContainerScanResult, error)

	// Hash Store Operations

	// CheckHash looks up a file hash in the scan history database.
	// Returns cached results if the hash was previously scanned.
	CheckHash(ctx context.Context, hash string) (*HashEntry, error)

	// StoreResult saves a scan result to the hash store for future lookups.
	StoreResult(ctx context.Context, result *ScanResult) error

	// GetScanHistory retrieves scan history filtered by time range,
	// infection status, or other criteria.
	GetScanHistory(ctx context.Context, filters HistoryFilter) ([]*HashEntry, error)

	// SearchHistory searches scan history by file path, hash, or threat name.
	SearchHistory(ctx context.Context, query string) ([]*HashEntry, error)

	// PruneHashStore removes hash entries older than the retention period.
	// Returns the number of entries deleted.
	PruneHashStore(ctx context.Context, olderThan time.Duration) (int, error)

	// Engine Management Operations

	// UpdateEngines updates all virus definition databases
	// (ClamAV, YARA, CAPA, etc.).
	UpdateEngines(ctx context.Context) error

	// GetEnabledEngines returns a list of currently active scanning engines.
	GetEnabledEngines() []string

	// GetEngineCount returns the number of enabled engines.
	GetEngineCount() int

	// IsEnabled returns whether DarkScan integration is enabled in configuration.
	IsEnabled() bool

	// Connection Management

	// GetConnectionStatus returns the current connection mode and health.
	GetConnectionStatus() ConnectionStatus

	// Close releases all resources and closes connections.
	Close() error
}

// ConnectionStatus represents the current state of the DarkScan client connection.
type ConnectionStatus struct {
	Mode            string    // "daemon", "library", or "cli"
	DaemonConnected bool      // True if connected to daemon
	SocketPath      string    // Unix socket path (if daemon mode)
	TCPAddress      string    // TCP address (if daemon mode)
	LastError       string    // Most recent connection error
	LastChecked     time.Time // Last connection health check
	Uptime          string    // Daemon uptime (if available)
}

// PrivacyScanResult represents the results of a browser privacy scan.
type PrivacyScanResult struct {
	Browser       string           // Browser name (chrome, firefox, etc.)
	ProfilePath   string           // Path to browser profile
	TrackersFound []PrivacyFinding // Detected tracking mechanisms
	TelemetryURLs []string         // Detected telemetry endpoints
	RiskLevel     string           // low, medium, high, critical
	ScanDuration  time.Duration    // Time taken for scan
}

// PrivacyFinding represents a single privacy issue (tracker, extension, etc.).
type PrivacyFinding struct {
	ID          string    // Unique finding identifier
	Type        string    // cookie, localStorage, extension, hijack, telemetry
	Name        string    // Display name
	Description string    // What this finding means
	Severity    string    // low, medium, high, critical
	Domain      string    // Associated domain
	Data        string    // Cookie value, extension ID, etc.
	Removable   bool      // Can be automatically removed
	Location    string    // File path or registry key
	DetectedAt  time.Time // When this was found
}

// PrivacyFilter specifies criteria for filtering privacy findings.
type PrivacyFilter struct {
	Browser  string // Filter by browser
	RiskLevel string // Filter by risk level
	Type     string // Filter by finding type
	Since    time.Time // Only findings after this time
}

// QuarantineInfo represents metadata about a quarantined file.
type QuarantineInfo struct {
	QuarantineID  string    // Unique identifier
	OriginalPath  string    // Original file location
	QuarantinedAt time.Time // When file was quarantined
	Threats       []Threat  // Detected threats
	FileSize      int64     // Original file size
	FileHash      string    // SHA256 hash
	Encrypted     bool      // Whether file is encrypted
}

// RuleRepository represents a YARA rule source.
type RuleRepository struct {
	URL         string    // GitHub or custom URL
	Branch      string    // Git branch
	LastUpdated time.Time // Last successful update
	RuleCount   int       // Number of rules installed
	Enabled     bool      // Whether this repo is active
}

// RuleInfo contains statistics about installed YARA rules.
type RuleInfo struct {
	TotalRules    int                // Total installed rules
	Repositories  []*RuleRepository  // Rule sources
	LastUpdate    time.Time          // Last update time
	RulesPath     string             // Where rules are stored
}

// Note: Profile type defined in profiles.go

// Note: FileTypeResult type defined in filetype.go

// Note: HashEntry and HistoryFilter types defined in hashstore.go
