package darkscan

// Config holds DarkScan integration configuration for AfterSec
type Config struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	UseCLI         bool          `yaml:"use_cli" json:"use_cli"`
	CLIBinaryPath  string        `yaml:"cli_binary_path" json:"cli_binary_path"`
	QuarantinePath string        `yaml:"quarantine_path" json:"quarantine_path"`
	CacheEnabled   bool          `yaml:"cache_enabled" json:"cache_enabled"`
	CacheTTL       string        `yaml:"cache_ttl" json:"cache_ttl"`
	APIEnabled     bool          `yaml:"api_enabled" json:"api_enabled"`
	APIPort        int           `yaml:"api_port" json:"api_port"`
	Engines        EnginesConfig `yaml:"engines" json:"engines"`
}

// EnginesConfig configures which scanning engines to enable
type EnginesConfig struct {
	ClamAV     ClamAVConfig     `yaml:"clamav" json:"clamav"`
	YARA       YARAConfig       `yaml:"yara" json:"yara"`
	CAPA       CAPAConfig       `yaml:"capa" json:"capa"`
	Viper      ViperConfig      `yaml:"viper" json:"viper"`
	VirusTotal VirusTotalConfig `yaml:"virustotal" json:"virustotal"`
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

// DefaultConfig returns sensible defaults for DarkScan integration
func DefaultConfig() *Config {
	return &Config{
		Enabled:        false,
		UseCLI:         true,
		CLIBinaryPath:  "darkscan",
		QuarantinePath: "quarantine",
		CacheEnabled:   true,
		CacheTTL:       "24h",
		APIEnabled:     false,
		APIPort:        8081,
		Engines: EnginesConfig{
			ClamAV: ClamAVConfig{
				Enabled:      false,
				DatabasePath: "/usr/local/share/clamav",
				AutoUpdate:   false,
			},
			YARA: YARAConfig{
				Enabled:   false,
				RulesPath: "",
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
		},
	}
}
