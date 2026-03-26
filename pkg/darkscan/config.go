package darkscan

// Config holds DarkScan integration configuration for AfterSec
type Config struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	Engines EnginesConfig `yaml:"engines" json:"engines"`
}

// EnginesConfig configures which scanning engines to enable
type EnginesConfig struct {
	ClamAV ClamAVConfig `yaml:"clamav" json:"clamav"`
	YARA   YARAConfig   `yaml:"yara" json:"yara"`
	CAPA   CAPAConfig   `yaml:"capa" json:"capa"`
	Viper  ViperConfig  `yaml:"viper" json:"viper"`
}

// ClamAVConfig configures the ClamAV engine
type ClamAVConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	DatabasePath string `yaml:"database_path" json:"database_path"`
	AutoUpdate   bool   `yaml:"auto_update" json:"auto_update"`
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

// DefaultConfig returns sensible defaults for DarkScan integration
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
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
		},
	}
}
