package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"howett.net/plist"
)

// SystemVersionInfo contains all system and engine version information
type SystemVersionInfo struct {
	XProtect     XProtectVersion     `json:"xprotect"`
	ClamAV       ClamAVVersion       `json:"clamav"`
	DarkScan     DarkScanVersion     `json:"darkscan"`
	AI           AIVersion           `json:"ai"`
	AfterSec     string              `json:"aftersec_version"`
	CollectedAt  time.Time           `json:"collected_at"`
}

// XProtectVersion contains XProtect definition information
type XProtectVersion struct {
	Version         string    `json:"version"`
	BuildVersion    int       `json:"build_version"`
	LastUpdate      time.Time `json:"last_update"`
	DefinitionCount int       `json:"definition_count"`
	Available       bool      `json:"available"`
	Error           string    `json:"error,omitempty"`
}

// ClamAVVersion contains ClamAV definition information
type ClamAVVersion struct {
	MainVersion     string    `json:"main_version"`
	DailyVersion    string    `json:"daily_version"`
	BytecodeVersion string    `json:"bytecode_version"`
	LastUpdate      time.Time `json:"last_update"`
	TotalSizeMB     float64   `json:"total_size_mb"`
	Available       bool      `json:"available"`
	Error           string    `json:"error,omitempty"`
}

// DarkScanVersion contains DarkScan engine information
type DarkScanVersion struct {
	EngineVersion   string   `json:"engine_version"`
	EnabledEngines  []string `json:"enabled_engines"`
	YARAVersion     string   `json:"yara_version"`
	CAPAVersion     string   `json:"capa_version"`
	Available       bool     `json:"available"`
	Error           string   `json:"error,omitempty"`
}

// AIVersion contains AI model information
type AIVersion struct {
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	GeminiModel     string `json:"gemini_model"`
	OpenAIModel     string `json:"openai_model"`
	AnthropicModel  string `json:"anthropic_model"`
	Available       bool   `json:"available"`
}

// GetSystemVersionInfo retrieves all system and engine version information
func GetSystemVersionInfo() (*SystemVersionInfo, error) {
	info := &SystemVersionInfo{
		AfterSec:    "1.0.0", // This should come from build info
		CollectedAt: time.Now(),
	}

	// Get XProtect version
	xprotect, err := getXProtectVersion()
	if err != nil {
		xprotect = &XProtectVersion{
			Available: false,
			Error:     err.Error(),
		}
	}
	info.XProtect = *xprotect

	// Get ClamAV version
	clamav, err := getClamAVVersion()
	if err != nil {
		clamav = &ClamAVVersion{
			Available: false,
			Error:     err.Error(),
		}
	}
	info.ClamAV = *clamav

	// Get DarkScan version
	darkscan := getDarkScanVersion()
	info.DarkScan = *darkscan

	// Get AI version (this will be populated from config)
	info.AI = AIVersion{
		Available: false,
	}

	return info, nil
}

// getXProtectVersion retrieves XProtect version information
func getXProtectVersion() (*XProtectVersion, error) {
	xprotectPath := "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"

	data, err := os.ReadFile(xprotectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read XProtect version file: %w", err)
	}

	var versionInfo struct {
		CFBundleShortVersionString string `plist:"CFBundleShortVersionString"`
		BuildVersion               int    `plist:"BuildVersion"`
	}

	if _, err := plist.Unmarshal(data, &versionInfo); err != nil {
		return nil, fmt.Errorf("failed to parse XProtect version: %w", err)
	}

	// Get last modified time of XProtect.plist to estimate update time
	xprotectPlist := "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist"
	fileInfo, err := os.Stat(xprotectPlist)
	var lastUpdate time.Time
	if err == nil {
		lastUpdate = fileInfo.ModTime()
	}

	// Count definitions in XProtect.plist (approximate)
	definitionCount := 0
	if plistData, err := os.ReadFile(xprotectPlist); err == nil {
		definitionCount = strings.Count(string(plistData), "<dict>")
	}

	return &XProtectVersion{
		Version:         versionInfo.CFBundleShortVersionString,
		BuildVersion:    versionInfo.BuildVersion,
		LastUpdate:      lastUpdate,
		DefinitionCount: definitionCount,
		Available:       true,
	}, nil
}

// getClamAVVersion retrieves ClamAV definition version information
func getClamAVVersion() (*ClamAVVersion, error) {
	// Try to get version from sigtool
	cmd := exec.Command("sigtool", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sigtool not available: %w", err)
	}

	version := &ClamAVVersion{
		Available: true,
	}

	// Parse sigtool output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "main.cvd") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				version.MainVersion = parts[1]
			}
		} else if strings.Contains(line, "daily.cvd") || strings.Contains(line, "daily.cld") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				version.DailyVersion = parts[1]
			}
		} else if strings.Contains(line, "bytecode.cvd") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				version.BytecodeVersion = parts[1]
			}
		}
	}

	// Try to get database statistics
	dbPaths := []string{
		"/var/lib/clamav",
		"/usr/local/share/clamav",
		"/usr/share/clamav",
		os.ExpandEnv("$HOME/.aftersec/clamav"),
	}

	var totalSize int64
	var lastMod time.Time
	for _, dbPath := range dbPaths {
		if info, err := os.Stat(dbPath); err == nil && info.IsDir() {
			entries, err := os.ReadDir(dbPath)
			if err == nil {
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".cvd") ||
					   strings.HasSuffix(entry.Name(), ".cld") ||
					   strings.HasSuffix(entry.Name(), ".cud") {
						if info, err := entry.Info(); err == nil {
							totalSize += info.Size()
							if info.ModTime().After(lastMod) {
								lastMod = info.ModTime()
							}
						}
					}
				}
			}
		}
	}

	if totalSize > 0 {
		version.TotalSizeMB = float64(totalSize) / (1024 * 1024)
		version.LastUpdate = lastMod
	}

	return version, nil
}

// getDarkScanVersion retrieves DarkScan engine information
func getDarkScanVersion() *DarkScanVersion {
	version := &DarkScanVersion{
		EngineVersion:  "1.0.0", // Should come from DarkScan package
		EnabledEngines: []string{},
		Available:      true,
	}

	// Check for YARA
	if cmd := exec.Command("yara", "--version"); cmd.Run() == nil {
		if output, err := cmd.CombinedOutput(); err == nil {
			version.YARAVersion = strings.TrimSpace(string(output))
			version.EnabledEngines = append(version.EnabledEngines, "YARA")
		}
	}

	// Check for CAPA
	if cmd := exec.Command("capa", "--version"); cmd.Run() == nil {
		if output, err := cmd.CombinedOutput(); err == nil {
			version.CAPAVersion = strings.TrimSpace(string(output))
			version.EnabledEngines = append(version.EnabledEngines, "CAPA")
		}
	}

	// Always include ClamAV and Viper as they're integrated
	version.EnabledEngines = append(version.EnabledEngines, "ClamAV", "Viper")

	return version
}

// FormatVersionInfo formats version information for display
func FormatVersionInfo(info *SystemVersionInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("AfterSec Version: %s\n\n", info.AfterSec))

	// XProtect
	sb.WriteString("XProtect Definitions:\n")
	if info.XProtect.Available {
		sb.WriteString(fmt.Sprintf("  Version: %s (Build %d)\n",
			info.XProtect.Version, info.XProtect.BuildVersion))
		sb.WriteString(fmt.Sprintf("  Last Update: %s\n",
			info.XProtect.LastUpdate.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("  Definitions: ~%d signatures\n",
			info.XProtect.DefinitionCount))
	} else {
		sb.WriteString(fmt.Sprintf("  Status: Not Available (%s)\n", info.XProtect.Error))
	}
	sb.WriteString("\n")

	// ClamAV
	sb.WriteString("ClamAV Definitions:\n")
	if info.ClamAV.Available {
		sb.WriteString(fmt.Sprintf("  Main: %s\n", info.ClamAV.MainVersion))
		sb.WriteString(fmt.Sprintf("  Daily: %s\n", info.ClamAV.DailyVersion))
		sb.WriteString(fmt.Sprintf("  Bytecode: %s\n", info.ClamAV.BytecodeVersion))
		if !info.ClamAV.LastUpdate.IsZero() {
			sb.WriteString(fmt.Sprintf("  Last Update: %s\n",
				info.ClamAV.LastUpdate.Format("2006-01-02 15:04:05")))
		}
		if info.ClamAV.TotalSizeMB > 0 {
			sb.WriteString(fmt.Sprintf("  Database Size: %.1f MB\n", info.ClamAV.TotalSizeMB))
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Status: Not Available (%s)\n", info.ClamAV.Error))
	}
	sb.WriteString("\n")

	// DarkScan
	sb.WriteString("DarkScan Engine:\n")
	if info.DarkScan.Available {
		sb.WriteString(fmt.Sprintf("  Version: %s\n", info.DarkScan.EngineVersion))
		sb.WriteString(fmt.Sprintf("  Enabled Engines: %s\n",
			strings.Join(info.DarkScan.EnabledEngines, ", ")))
		if info.DarkScan.YARAVersion != "" {
			sb.WriteString(fmt.Sprintf("  YARA: %s\n", info.DarkScan.YARAVersion))
		}
		if info.DarkScan.CAPAVersion != "" {
			sb.WriteString(fmt.Sprintf("  CAPA: %s\n", info.DarkScan.CAPAVersion))
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Status: Not Available (%s)\n", info.DarkScan.Error))
	}
	sb.WriteString("\n")

	// AI Models
	sb.WriteString("AI Models:\n")
	if info.AI.Available {
		sb.WriteString(fmt.Sprintf("  Active Provider: %s\n", info.AI.Provider))
		sb.WriteString(fmt.Sprintf("  Active Model: %s\n", info.AI.Model))
		sb.WriteString(fmt.Sprintf("  Gemini: %s\n", info.AI.GeminiModel))
		sb.WriteString(fmt.Sprintf("  OpenAI: %s\n", info.AI.OpenAIModel))
		sb.WriteString(fmt.Sprintf("  Anthropic: %s\n", info.AI.AnthropicModel))
	} else {
		sb.WriteString("  Status: Not Configured\n")
	}

	sb.WriteString(fmt.Sprintf("\nCollected: %s\n",
		info.CollectedAt.Format("2006-01-02 15:04:05")))

	return sb.String()
}

// FormatVersionJSON formats version information as JSON
func FormatVersionJSON(info *SystemVersionInfo) (string, error) {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
