package darkscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CLIClient wraps the darkscancli command-line tool
type CLIClient struct {
	binaryPath string
	configPath string
	config     *Config
}

// CLIScanOutput represents the JSON output from darkscancli
type CLIScanOutput struct {
	Summary struct {
		TotalFiles    int    `json:"total_files"`
		InfectedFiles int    `json:"infected_files"`
		CleanFiles    int    `json:"clean_files"`
		Errors        int    `json:"errors"`
		ScanDuration  string `json:"scan_duration"`
	} `json:"summary"`
	Results []CLIFileResult `json:"results"`
}

// CLIFileResult represents a single file scan result from darkscancli
type CLIFileResult struct {
	FilePath string       `json:"file_path"`
	Infected bool         `json:"infected"`
	Threats  []CLIThreat  `json:"threats,omitempty"`
	Error    string       `json:"error,omitempty"`
}

// CLIThreat represents a threat detected by darkscancli
type CLIThreat struct {
	Engine      string `json:"engine"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// NewCLIClient creates a new CLI-based DarkScan client
func NewCLIClient(cfg *Config, binaryPath string) (*CLIClient, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if binaryPath == "" {
		binaryPath = "darkscan"
	}

	if _, err := exec.LookPath(binaryPath); err != nil {
		return nil, fmt.Errorf("darkscancli binary not found: %w", err)
	}

	return &CLIClient{
		binaryPath: binaryPath,
		config:     cfg,
	}, nil
}

// ScanFile scans a single file using darkscancli
func (c *CLIClient) ScanFile(ctx context.Context, path string) (*ScanResult, error) {
	args := []string{"scan", path, "-o", "json"}

	if c.configPath != "" {
		args = append(args, "-c", c.configPath)
	}

	args = c.addEngineFlags(args)

	cmd := exec.CommandContext(ctx, c.binaryPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("scan timeout: %w", ctx.Err())
		}
		return &ScanResult{
			FilePath: path,
			Error:    fmt.Errorf("darkscancli execution failed: %w", err),
		}, err
	}

	cliOutput, parseErr := c.parseOutput(output)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse darkscancli output: %w", parseErr)
	}

	if len(cliOutput.Results) == 0 {
		return &ScanResult{
			FilePath: path,
			Error:    fmt.Errorf("no scan results returned"),
		}, nil
	}

	return c.convertCLIResult(&cliOutput.Results[0]), nil
}

// ScanDirectory scans a directory using darkscancli
func (c *CLIClient) ScanDirectory(ctx context.Context, path string, recursive bool) ([]*ScanResult, error) {
	args := []string{"scan", path, "-o", "json"}

	if recursive {
		args = append(args, "-r")
	}

	if c.configPath != "" {
		args = append(args, "-c", c.configPath)
	}

	args = c.addEngineFlags(args)

	cmd := exec.CommandContext(ctx, c.binaryPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("scan timeout: %w", ctx.Err())
		}
		return nil, fmt.Errorf("darkscancli execution failed: %w", err)
	}

	cliOutput, parseErr := c.parseOutput(output)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse darkscancli output: %w", parseErr)
	}

	results := make([]*ScanResult, 0, len(cliOutput.Results))
	for _, cliResult := range cliOutput.Results {
		results = append(results, c.convertCLIResult(&cliResult))
	}

	return results, nil
}

// QuickScan performs a fast scan using darkscancli
func (c *CLIClient) QuickScan(ctx context.Context, path string) (bool, error) {
	result, err := c.ScanFile(ctx, path)
	if err != nil {
		return false, err
	}
	return result.Infected, nil
}

// ScanWithReport performs a comprehensive scan and returns a detailed report
func (c *CLIClient) ScanWithReport(ctx context.Context, path string) (*IntegrationReport, error) {
	start := time.Now()

	result, err := c.ScanFile(ctx, path)
	duration := time.Since(start)

	report := &IntegrationReport{
		FilePath:     path,
		Scanned:      true,
		Infected:     result.Infected,
		Threats:      result.Threats,
		Engines:      c.getEnabledEngines(),
		ScanDuration: duration,
		Error:        err,
	}

	report.ThreatLevel = c.calculateThreatLevel(result)

	return report, err
}

// RealTimeScan performs a fast scan optimized for real-time protection
func (c *CLIClient) RealTimeScan(ctx context.Context, path string, timeoutSeconds int) (bool, ThreatLevel, error) {
	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	result, err := c.ScanFile(scanCtx, path)
	if err != nil {
		if err == context.DeadlineExceeded {
			return false, ThreatNone, fmt.Errorf("scan timeout after %d seconds", timeoutSeconds)
		}
		return false, ThreatNone, err
	}

	threatLevel := c.calculateThreatLevel(result)
	shouldBlock := result.Infected && threatLevel >= ThreatHigh

	return shouldBlock, threatLevel, nil
}

// UpdateEngines updates virus definitions using darkscancli
func (c *CLIClient) UpdateEngines(ctx context.Context) error {
	args := []string{"update"}

	if c.configPath != "" {
		args = append(args, "-c", c.configPath)
	}

	cmd := exec.CommandContext(ctx, c.binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("update failed: %w (output: %s)", err, string(output))
	}
	return nil
}

// Close releases resources (no-op for CLI client)
func (c *CLIClient) Close() error {
	return nil
}

// IsEnabled returns whether DarkScan is enabled
func (c *CLIClient) IsEnabled() bool {
	return c.config.Enabled
}

// GetEnabledEngines returns a list of enabled engine names
func (c *CLIClient) GetEnabledEngines() []string {
	return c.getEnabledEngines()
}

// GetEngineCount returns the number of enabled engines
func (c *CLIClient) GetEngineCount() int {
	return len(c.getEnabledEngines())
}

// parseOutput parses the JSON output from darkscancli
func (c *CLIClient) parseOutput(output []byte) (*CLIScanOutput, error) {
	outputStr := string(output)

	jsonStart := strings.Index(outputStr, "{")
	if jsonStart == -1 {
		return nil, fmt.Errorf("no JSON output found in darkscancli response")
	}

	jsonData := outputStr[jsonStart:]

	var result CLIScanOutput
	if err := json.Unmarshal([]byte(jsonData), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &result, nil
}

// convertCLIResult converts CLI result to ScanResult
func (c *CLIClient) convertCLIResult(cliResult *CLIFileResult) *ScanResult {
	result := &ScanResult{
		FilePath:    cliResult.FilePath,
		Infected:    cliResult.Infected,
		Threats:     make([]Threat, 0, len(cliResult.Threats)),
		EngineCount: len(cliResult.Threats),
	}

	if cliResult.Error != "" {
		result.Error = fmt.Errorf("%s", cliResult.Error)
	}

	for _, cliThreat := range cliResult.Threats {
		result.Threats = append(result.Threats, Threat{
			Name:        cliThreat.Name,
			Severity:    cliThreat.Severity,
			Description: cliThreat.Description,
			Engine:      cliThreat.Engine,
		})
	}

	return result
}

// calculateThreatLevel determines overall threat level from scan results
func (c *CLIClient) calculateThreatLevel(result *ScanResult) ThreatLevel {
	if !result.Infected || len(result.Threats) == 0 {
		return ThreatNone
	}

	maxLevel := ThreatLow

	for _, threat := range result.Threats {
		level := parseThreatSeverity(threat.Severity)
		if level > maxLevel {
			maxLevel = level
		}
	}

	if result.EngineCount >= 2 && len(result.Threats) > 0 && maxLevel < ThreatCritical {
		maxLevel++
	}

	return maxLevel
}

// getEnabledEngines returns a list of enabled engine names
func (c *CLIClient) getEnabledEngines() []string {
	var engines []string

	// Document and Heuristics are enabled by default in darkscancli
	engines = append(engines, "Document", "Heuristics")

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

	return engines
}

// addEngineFlags adds engine-specific flags to the command
func (c *CLIClient) addEngineFlags(args []string) []string {
	if c.config.Engines.ClamAV.Enabled {
		args = append(args, "--clamav")
	}

	if c.config.Engines.YARA.Enabled {
		args = append(args, "--yara")
		if c.config.Engines.YARA.RulesPath != "" {
			args = append(args, "--yara-rules", c.config.Engines.YARA.RulesPath)
		}
	}

	if c.config.Engines.CAPA.Enabled {
		args = append(args, "--capa")
		if c.config.Engines.CAPA.RulesPath != "" {
			args = append(args, "--capa-rules", c.config.Engines.CAPA.RulesPath)
		}
	}

	if c.config.Engines.Viper.Enabled {
		args = append(args, "--viper")
	}

	return args
}

// SetConfigPath sets the path to the darkscancli config file
func (c *CLIClient) SetConfigPath(path string) {
	c.configPath = path
}
