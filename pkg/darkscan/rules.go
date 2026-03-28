package darkscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RuleManager manages YARA rule repositories and updates
type RuleManager struct {
	config        *Config
	repositories  []*RuleRepository
	mu            sync.RWMutex
	enabled       bool
	lastUpdate    time.Time
	updateRunning bool
}

// Note: RuleRepository and RuleInfo types are defined in interface.go

// NewRuleManager creates a new YARA rule manager
func NewRuleManager(cfg *Config) (*RuleManager, error) {
	if !cfg.RuleManager.Enabled {
		return &RuleManager{enabled: false}, nil
	}

	rulesPath := cfg.RuleManager.RulesPath
	if rulesPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		rulesPath = filepath.Join(homeDir, ".aftersec", "darkscan", "rules")
	}

	// Expand tilde
	if len(rulesPath) > 0 && rulesPath[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		rulesPath = filepath.Join(homeDir, rulesPath[1:])
	}

	// Create rules directory
	if err := os.MkdirAll(rulesPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rules directory: %w", err)
	}

	rm := &RuleManager{
		config:       cfg,
		repositories: []*RuleRepository{},
		enabled:      true,
	}

	// Load configured repositories
	for _, repoURL := range cfg.RuleManager.Repositories {
		repo := &RuleRepository{
			URL:     repoURL,
			Branch:  "main",
			Enabled: true,
		}
		rm.repositories = append(rm.repositories, repo)
	}

	return rm, nil
}

// UpdateRules updates all rule repositories
func (rm *RuleManager) UpdateRules(ctx context.Context) error {
	if !rm.enabled {
		return fmt.Errorf("rule manager not enabled")
	}

	rm.mu.Lock()
	if rm.updateRunning {
		rm.mu.Unlock()
		return fmt.Errorf("update already in progress")
	}
	rm.updateRunning = true
	rm.mu.Unlock()

	defer func() {
		rm.mu.Lock()
		rm.updateRunning = false
		rm.lastUpdate = time.Now()
		rm.mu.Unlock()
	}()

	var errors []error
	for _, repo := range rm.repositories {
		if !repo.Enabled {
			continue
		}

		if err := rm.updateRepository(ctx, repo); err != nil {
			errors = append(errors, fmt.Errorf("failed to update %s: %w", repo.URL, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("rule update errors: %v", errors)
	}

	return nil
}

// getLocalPath returns the local filesystem path for a repository
func (rm *RuleManager) getLocalPath(repo *RuleRepository) string {
	rulesPath := rm.config.RuleManager.RulesPath
	if rulesPath == "" {
		homeDir, _ := os.UserHomeDir()
		rulesPath = filepath.Join(homeDir, ".aftersec", "darkscan", "rules")
	}
	return filepath.Join(rulesPath, sanitizeRepoName(repo.URL))
}

// updateRepository updates a single repository
func (rm *RuleManager) updateRepository(ctx context.Context, repo *RuleRepository) error {
	localPath := rm.getLocalPath(repo)

	// Create local directory
	if err := os.MkdirAll(localPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Check if it's a GitHub repository
	if strings.Contains(repo.URL, "github.com") {
		return rm.downloadGitHubRepo(ctx, repo, localPath)
	}

	// For direct URL downloads
	return rm.downloadRulesFromURL(ctx, repo.URL, localPath)
}

// downloadGitHubRepo downloads rules from a GitHub repository
func (rm *RuleManager) downloadGitHubRepo(ctx context.Context, repo *RuleRepository, localPath string) error {
	// Convert GitHub URL to raw content URL
	// Example: https://github.com/Yara-Rules/rules -> https://raw.githubusercontent.com/Yara-Rules/rules/main/

	parts := strings.Split(repo.URL, "github.com/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid GitHub URL: %s", repo.URL)
	}

	repoPath := strings.TrimSuffix(parts[1], "/")
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/", repoPath, repo.Branch)

	// Download a known index file or specific rules
	// For simplicity, try downloading a few common rule files
	ruleFiles := []string{
		"malware/malware_index.yar",
		"CVE_Rules/CVE_Rules_index.yar",
		"antidebug/antidebug_index.yar",
		"crypto/crypto_index.yar",
	}

	downloadedCount := 0
	for _, ruleFile := range ruleFiles {
		fileURL := rawURL + ruleFile
		destPath := filepath.Join(localPath, ruleFile)

		if err := rm.downloadFile(ctx, fileURL, destPath); err == nil {
			downloadedCount++
		}
	}

	if downloadedCount == 0 {
		return fmt.Errorf("no rule files downloaded")
	}

	repo.LastUpdated = time.Now()
	repo.RuleCount = downloadedCount

	return nil
}

// downloadRulesFromURL downloads rules from a direct URL
func (rm *RuleManager) downloadRulesFromURL(ctx context.Context, url, destPath string) error {
	return rm.downloadFile(ctx, url, destPath)
}

// downloadFile downloads a file from URL to destination
func (rm *RuleManager) downloadFile(ctx context.Context, url, destPath string) error {
	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Execute request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Create destination file
	file, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy content
	if _, err := io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ListRuleRepositories returns all configured repositories
func (rm *RuleManager) ListRuleRepositories() ([]*RuleRepository, error) {
	if !rm.enabled {
		return nil, fmt.Errorf("rule manager not enabled")
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Return a copy to avoid concurrent modification
	repos := make([]*RuleRepository, len(rm.repositories))
	copy(repos, rm.repositories)

	return repos, nil
}

// AddRuleRepository adds a new rule repository
func (rm *RuleManager) AddRuleRepository(ctx context.Context, url, branch string) error {
	if !rm.enabled {
		return fmt.Errorf("rule manager not enabled")
	}

	if branch == "" {
		branch = "main"
	}

	repo := &RuleRepository{
		URL:     url,
		Branch:  branch,
		Enabled: true,
	}

	rm.mu.Lock()
	rm.repositories = append(rm.repositories, repo)
	rm.mu.Unlock()

	// Immediately update the new repository
	return rm.updateRepository(ctx, repo)
}

// RemoveRuleRepository removes a rule repository
func (rm *RuleManager) RemoveRuleRepository(url string) error {
	if !rm.enabled {
		return fmt.Errorf("rule manager not enabled")
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, repo := range rm.repositories {
		if repo.URL == url {
			// Get local path before removing
			localPath := rm.getLocalPath(repo)

			// Remove from slice
			rm.repositories = append(rm.repositories[:i], rm.repositories[i+1:]...)

			// Optionally remove local files
			if err := os.RemoveAll(localPath); err != nil {
				return fmt.Errorf("failed to remove local files: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("repository not found: %s", url)
}

// GetRuleInfo returns information about installed rules
func (rm *RuleManager) GetRuleInfo() (*RuleInfo, error) {
	if !rm.enabled {
		return nil, fmt.Errorf("rule manager not enabled")
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	totalRules := 0
	for _, repo := range rm.repositories {
		totalRules += repo.RuleCount
	}

	info := &RuleInfo{
		TotalRules:   totalRules,
		Repositories: rm.repositories,
		LastUpdate:   rm.lastUpdate,
		RulesPath:    rm.config.RuleManager.RulesPath,
	}

	return info, nil
}

// StartAutoUpdate starts automatic rule updates in background
func (rm *RuleManager) StartAutoUpdate(ctx context.Context) {
	if !rm.enabled || !rm.config.RuleManager.AutoUpdate {
		return
	}

	interval, err := time.ParseDuration(rm.config.RuleManager.UpdateInterval)
	if err != nil || interval == 0 {
		interval = 6 * time.Hour // Default
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := rm.UpdateRules(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "Auto-update failed: %v\n", err)
				}
			}
		}
	}()
}

// sanitizeRepoName converts a repository URL to a safe directory name
func sanitizeRepoName(url string) string {
	// Remove protocol
	name := strings.TrimPrefix(url, "https://")
	name = strings.TrimPrefix(name, "http://")

	// Replace invalid characters
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "?", "_")
	name = strings.ReplaceAll(name, "&", "_")

	return name
}
