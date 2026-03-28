package darkscan

// Config holds DarkScan integration configuration for AfterSec
type Config struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	UseCLI         bool          `yaml:"use_cli" json:"use_cli"` // Deprecated: use UseDaemon instead
	CLIBinaryPath  string        `yaml:"cli_binary_path" json:"cli_binary_path"`

	// Daemon configuration (hybrid mode)
	UseDaemon         bool   `yaml:"use_daemon" json:"use_daemon"`                  // Try daemon first
	DaemonSocket      string `yaml:"daemon_socket" json:"daemon_socket"`            // Unix socket path
	DaemonTCPAddr     string `yaml:"daemon_tcp_addr" json:"daemon_tcp_addr"`        // TCP fallback address
	FallbackToLibrary bool   `yaml:"fallback_to_library" json:"fallback_to_library"` // Fallback if daemon unavailable
	DaemonToken       string `yaml:"daemon_token" json:"daemon_token"`              // Bearer token for daemon API

	// Feature configuration
	Privacy     PrivacyConfig     `yaml:"privacy" json:"privacy"`
	HashStore   HashStoreConfig   `yaml:"hash_store" json:"hash_store"`
	RuleManager RuleManagerConfig `yaml:"rule_manager" json:"rule_manager"`
	Profiles    ProfilesConfig    `yaml:"profiles" json:"profiles"`
	FileType    FileTypeConfig    `yaml:"file_type" json:"file_type"`
	Quarantine  QuarantineConfig  `yaml:"quarantine" json:"quarantine"`

	// Legacy fields (maintain backwards compatibility)
	QuarantinePath string `yaml:"quarantine_path" json:"quarantine_path"` // Deprecated: use Quarantine.Path
	CacheEnabled   bool   `yaml:"cache_enabled" json:"cache_enabled"`     // Deprecated: use HashStore.Enabled
	CacheTTL       string `yaml:"cache_ttl" json:"cache_ttl"`             // Deprecated: use HashStore.CacheTTL
	APIEnabled     bool   `yaml:"api_enabled" json:"api_enabled"`
	APIPort        int    `yaml:"api_port" json:"api_port"`

	Engines EnginesConfig `yaml:"engines" json:"engines"`
}

// EnginesConfig configures which scanning engines to enable
type EnginesConfig struct {
	Document   DocumentConfig   `yaml:"document" json:"document"`
	Heuristics HeuristicsConfig `yaml:"heuristics" json:"heuristics"`
	ClamAV     ClamAVConfig     `yaml:"clamav" json:"clamav"`
	YARA       YARAConfig       `yaml:"yara" json:"yara"`
	CAPA       CAPAConfig       `yaml:"capa" json:"capa"`
	Viper      ViperConfig      `yaml:"viper" json:"viper"`
	VirusTotal VirusTotalConfig `yaml:"virustotal" json:"virustotal"`
	Sandbox    SandboxConfig    `yaml:"sandbox" json:"sandbox"`
}

// SandboxConfig configures the Unicorn CPU emulation engine
type SandboxConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// DocumentConfig configures the Document parsing engine
type DocumentConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// HeuristicsConfig configures the Heuristics engine
type HeuristicsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// ClamAVConfig configures the ClamAV engine
type ClamAVConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	DatabasePath string `yaml:"database_path" json:"database_path"`
	AutoUpdate   bool   `yaml:"auto_update" json:"auto_update"`
	MirrorURL    string `yaml:"mirror_url" json:"mirror_url"` // Custom mirror server for definition updates
}

// YARAConfig configures the YARA engine
type YARAConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	RulesPath string `yaml:"rules_path" json:"rules_path"`
}

// CAPAConfig configures the CAPA engine
type CAPAConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	ExePath   string `yaml:"exe_path" json:"exe_path"`
	RulesPath string `yaml:"rules_path" json:"rules_path"`
}

// ViperConfig configures the Viper framework engine
type ViperConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	ExePath     string `yaml:"exe_path" json:"exe_path"`
	ProjectName string `yaml:"project_name" json:"project_name"`
}

// VirusTotalConfig configures the VirusTotal engine
type VirusTotalConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	APIKey  string `yaml:"api_key" json:"api_key"`
}

// PrivacyConfig configures the privacy scanner
type PrivacyConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	ScanBrowsers     []string `yaml:"scan_browsers" json:"scan_browsers"`         // Browsers to scan: chrome, firefox, safari, edge, brave
	ScanApps         bool     `yaml:"scan_apps" json:"scan_apps"`                 // Scan application telemetry
	AutoScanInterval string   `yaml:"auto_scan_interval" json:"auto_scan_interval"` // e.g., "24h"
	BlockTrackers    bool     `yaml:"block_trackers" json:"block_trackers"`       // Auto-quarantine tracking libs
}

// HashStoreConfig configures the scan hash cache and history database
type HashStoreConfig struct {
	Enabled          bool   `yaml:"enabled" json:"enabled"`
	DatabasePath     string `yaml:"database_path" json:"database_path"`           // SQLite database location
	DeduplicateScans bool   `yaml:"deduplicate_scans" json:"deduplicate_scans"`   // Skip scanning known hashes
	RetentionDays    int    `yaml:"retention_days" json:"retention_days"`         // Auto-prune entries older than N days
	CacheTTL         string `yaml:"cache_ttl" json:"cache_ttl"`                   // How long to trust cached results
}

// RuleManagerConfig configures YARA rule auto-updates
type RuleManagerConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	AutoUpdate     bool     `yaml:"auto_update" json:"auto_update"`               // Automatically download rule updates
	UpdateInterval string   `yaml:"update_interval" json:"update_interval"`       // e.g., "6h"
	Repositories   []string `yaml:"repositories" json:"repositories"`             // GitHub rule repositories
	RulesPath      string   `yaml:"rules_path" json:"rules_path"`                 // Where to store downloaded rules
}

// ProfilesConfig configures scan profile presets
type ProfilesConfig struct {
	Enabled        bool              `yaml:"enabled" json:"enabled"`
	DefaultProfile string            `yaml:"default_profile" json:"default_profile"` // quick, standard, deep, forensic, safe
	CustomProfiles map[string]string `yaml:"custom_profiles" json:"custom_profiles"` // name -> path mapping
}

// FileTypeConfig configures file type identification
type FileTypeConfig struct {
	Enabled          bool `yaml:"enabled" json:"enabled"`
	DetectSpoofing   bool `yaml:"detect_spoofing" json:"detect_spoofing"`     // Detect files with mismatched extensions
	VerifyExtensions bool `yaml:"verify_extensions" json:"verify_extensions"` // Verify extension matches content
}

// QuarantineConfig configures enhanced quarantine management
type QuarantineConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Path           string `yaml:"path" json:"path"`                         // Quarantine directory location
	Encrypt        bool   `yaml:"encrypt" json:"encrypt"`                   // Encrypt quarantined files
	MaxSizeMB      int    `yaml:"max_size_mb" json:"max_size_mb"`           // Maximum total quarantine size
	AutoDeleteDays int    `yaml:"auto_delete_days" json:"auto_delete_days"` // Auto-delete files older than N days
}

// DefaultConfig returns sensible defaults for DarkScan integration
func DefaultConfig() *Config {
	return &Config{
		Enabled:        false,
		UseCLI:         false, // Deprecated
		CLIBinaryPath:  "darkscan",

		// Daemon configuration (hybrid mode)
		UseDaemon:         true, // Enabled by default for resilience
		DaemonSocket:      "/tmp/darkscand.sock",
		DaemonTCPAddr:     "127.0.0.1:8080",
		FallbackToLibrary: true, // Always fallback if daemon unavailable
		DaemonToken:       "",   // Default to no token

		// Privacy scanner
		Privacy: PrivacyConfig{
			Enabled:          false, // Opt-in feature
			ScanBrowsers:     []string{"chrome", "firefox", "safari"},
			ScanApps:         false,
			AutoScanInterval: "24h",
			BlockTrackers:    false,
		},

		// Hash store and scan history
		HashStore: HashStoreConfig{
			Enabled:          true, // Enabled by default for performance
			DatabasePath:     "~/.aftersec/darkscan/hashes.db",
			DeduplicateScans: true,
			RetentionDays:    90,
			CacheTTL:         "24h",
		},

		// YARA rule management
		RuleManager: RuleManagerConfig{
			Enabled:        true,
			AutoUpdate:     true,
			UpdateInterval: "6h",
			Repositories: []string{
				"https://github.com/Yara-Rules/rules",
			},
			RulesPath: "~/.aftersec/darkscan/rules",
		},

		// Scan profiles
		Profiles: ProfilesConfig{
			Enabled:        true,
			DefaultProfile: "standard",
			CustomProfiles: make(map[string]string),
		},

		// File type identification
		FileType: FileTypeConfig{
			Enabled:          true,
			DetectSpoofing:   true,
			VerifyExtensions: true,
		},

		// Enhanced quarantine
		Quarantine: QuarantineConfig{
			Enabled:        true,
			Path:           "~/.aftersec/quarantine",
			Encrypt:        false,
			MaxSizeMB:      1000,
			AutoDeleteDays: 30,
		},

		// Legacy fields (maintain backwards compatibility)
		QuarantinePath: "quarantine",
		CacheEnabled:   true,
		CacheTTL:       "24h",
		APIEnabled:     false,
		APIPort:        8081,

		Engines: EnginesConfig{
			Document: DocumentConfig{
				Enabled: true,
			},
			Heuristics: HeuristicsConfig{
				Enabled: true,
			},
			ClamAV: ClamAVConfig{
				Enabled:      false,
				DatabasePath: "/usr/local/share/clamav",
				AutoUpdate:   false,
			},
			YARA: YARAConfig{
				Enabled:   false,
				RulesPath: "~/.aftersec/darkscan/rules", // Managed by RuleManager
			},
			CAPA: CAPAConfig{
				Enabled:   false,
				ExePath:   "capa",
				RulesPath: "",
			},
			Viper: ViperConfig{
				Enabled:     false,
				ExePath:     "viper-cli",
				ProjectName: "aftersec",
			},
			VirusTotal: VirusTotalConfig{
				Enabled: false,
				APIKey:  "",
			},
			Sandbox: SandboxConfig{
				Enabled: false,
			},
		},
	}
}
