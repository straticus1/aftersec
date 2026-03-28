package darkscan

import (
	"fmt"
	"sync"
)

// ProfileManager manages scan profiles for different use cases
type ProfileManager struct {
	profiles map[string]*Profile
	mu       sync.RWMutex
	enabled  bool
}

// Profile represents a scan configuration preset
type Profile struct {
	Name        string
	Description string
	Engines     []string
	Timeout     int
	MaxFileSize int64
	Recursive   bool
	FollowLinks bool
	Custom      bool
}

// NewProfileManager creates a new profile manager
func NewProfileManager(cfg *Config) (*ProfileManager, error) {
	if !cfg.Profiles.Enabled {
		return &ProfileManager{enabled: false}, nil
	}

	pm := &ProfileManager{
		profiles: make(map[string]*Profile),
		enabled:  true,
	}

	// Register built-in profiles
	registerBuiltInProfiles(pm)

	return pm, nil
}

// registerBuiltInProfiles registers standard scanning profiles
func registerBuiltInProfiles(pm *ProfileManager) {
	profiles := []*Profile{
		{
			Name:        "quick",
			Description: "Fast scan with essential engines only",
			Engines:     []string{"clamav"},
			Timeout:     30,
			MaxFileSize: 10 * 1024 * 1024, // 10MB
			Recursive:   false,
			FollowLinks: false,
			Custom:      false,
		},
		{
			Name:        "standard",
			Description: "Balanced scan with multiple engines",
			Engines:     []string{"clamav", "yara"},
			Timeout:     120,
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			Recursive:   true,
			FollowLinks: false,
			Custom:      false,
		},
		{
			Name:        "deep",
			Description: "Thorough scan with all engines",
			Engines:     []string{"clamav", "yara", "capa", "viper"},
			Timeout:     600,
			MaxFileSize: 500 * 1024 * 1024, // 500MB
			Recursive:   true,
			FollowLinks: true,
			Custom:      false,
		},
		{
			Name:        "forensic",
			Description: "Comprehensive forensic analysis",
			Engines:     []string{"clamav", "yara", "capa", "viper", "document", "heuristics"},
			Timeout:     1800,
			MaxFileSize: 1024 * 1024 * 1024, // 1GB
			Recursive:   true,
			FollowLinks: true,
			Custom:      false,
		},
		{
			Name:        "safe",
			Description: "Conservative scan for production environments",
			Engines:     []string{"clamav"},
			Timeout:     60,
			MaxFileSize: 50 * 1024 * 1024, // 50MB
			Recursive:   false,
			FollowLinks: false,
			Custom:      false,
		},
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, p := range profiles {
		pm.profiles[p.Name] = p
	}
}

// ApplyProfile applies a profile to the configuration
func (pm *ProfileManager) ApplyProfile(profileName string) (*Profile, error) {
	if !pm.enabled {
		return nil, fmt.Errorf("profile manager not enabled")
	}

	pm.mu.RLock()
	profile, ok := pm.profiles[profileName]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("profile not found: %s", profileName)
	}

	return profile, nil
}

// ListProfiles returns all available profiles
func (pm *ProfileManager) ListProfiles() ([]*Profile, error) {
	if !pm.enabled {
		return nil, fmt.Errorf("profile manager not enabled")
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	profiles := make([]*Profile, 0, len(pm.profiles))
	for _, profile := range pm.profiles {
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

// GetProfile retrieves a specific profile
func (pm *ProfileManager) GetProfile(name string) (*Profile, error) {
	if !pm.enabled {
		return nil, fmt.Errorf("profile manager not enabled")
	}

	pm.mu.RLock()
	profile, ok := pm.profiles[name]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	return profile, nil
}

// CreateCustomProfile creates a new custom profile
func (pm *ProfileManager) CreateCustomProfile(profile *Profile) error {
	if !pm.enabled {
		return fmt.Errorf("profile manager not enabled")
	}

	profile.Custom = true

	pm.mu.Lock()
	pm.profiles[profile.Name] = profile
	pm.mu.Unlock()

	return nil
}

// DeleteCustomProfile deletes a custom profile
func (pm *ProfileManager) DeleteCustomProfile(name string) error {
	if !pm.enabled {
		return fmt.Errorf("profile manager not enabled")
	}

	// Check if it's a built-in profile
	builtInProfiles := []string{"quick", "standard", "deep", "forensic", "safe"}
	for _, builtin := range builtInProfiles {
		if name == builtin {
			return fmt.Errorf("cannot delete built-in profile: %s", name)
		}
	}

	pm.mu.Lock()
	delete(pm.profiles, name)
	pm.mu.Unlock()

	return nil
}

// ApplyProfileToConfig applies profile settings to a DarkScan config
func ApplyProfileToConfig(cfg *Config, profile *Profile) {
	// Update engine configuration based on profile
	cfg.Engines.ClamAV.Enabled = contains(profile.Engines, "clamav")
	cfg.Engines.YARA.Enabled = contains(profile.Engines, "yara")
	cfg.Engines.CAPA.Enabled = contains(profile.Engines, "capa")
	cfg.Engines.Viper.Enabled = contains(profile.Engines, "viper")
	cfg.Engines.Document.Enabled = contains(profile.Engines, "document")
	cfg.Engines.Heuristics.Enabled = contains(profile.Engines, "heuristics")
	cfg.Engines.VirusTotal.Enabled = contains(profile.Engines, "virustotal")

	// Note: Timeout and MaxFileSize are typically scanner-level settings
	// and would be applied during scan execution
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
