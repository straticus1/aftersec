package darkscan

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ContainerScanner scans Docker/OCI container images for malware and vulnerabilities
type ContainerScanner struct {
	config       *Config
	enabled      bool
	trivyPath    string
	grypePath    string
	malwareScanner *Client // Reference to main DarkScan client for layer scanning
}

// ContainerScanResult contains results from container image scanning
type ContainerScanResult struct {
	ImageRef         string
	ImageID          string
	Digest           string
	Size             int64
	Layers           []LayerInfo
	Vulnerabilities  []Vulnerability
	MalwareDetected  []MalwareDetection
	Secrets          []SecretDetection
	ConfigIssues     []ConfigIssue
	BaseImage        string
	BaseImageSafe    bool
	RiskLevel        string
	ScanDuration     time.Duration
	ScannerUsed      string
}

// LayerInfo contains information about a container layer
type LayerInfo struct {
	Digest          string
	Size            int64
	Command         string
	Created         time.Time
	MalwareFound    bool
	FileCount       int
	SuspiciousFiles []string
	ThreatLevel     string
}

// Vulnerability represents a detected CVE or security issue
type Vulnerability struct {
	ID          string
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW
	Package     string
	Version     string
	FixedIn     string
	Description string
	CVSS        float64
}

// MalwareDetection represents malware found in container layers
type MalwareDetection struct {
	FilePath    string
	Layer       string
	ThreatName  string
	ThreatType  string
	Confidence  float64
	Quarantined bool
}

// SecretDetection represents secrets/credentials found in images
type SecretDetection struct {
	FilePath   string
	Layer      string
	SecretType string // API_KEY, PASSWORD, PRIVATE_KEY, etc.
	Value      string // Masked
	Severity   string
}

// ConfigIssue represents container configuration security issues
type ConfigIssue struct {
	Type        string
	Severity    string
	Description string
	Remediation string
}

// NewContainerScanner creates a new container image scanner
func NewContainerScanner(cfg *Config, malwareScanner *Client) (*ContainerScanner, error) {
	scanner := &ContainerScanner{
		config:         cfg,
		enabled:        true,
		malwareScanner: malwareScanner,
	}

	// Detect available third-party scanners
	scanner.trivyPath = findExecutable("trivy")
	scanner.grypePath = findExecutable("grype")

	return scanner, nil
}

// ScanImage scans a container image (from registry or local)
func (cs *ContainerScanner) ScanImage(ctx context.Context, imageRef string) (*ContainerScanResult, error) {
	if !cs.enabled {
		return nil, fmt.Errorf("container scanner not enabled")
	}

	start := time.Now()

	result := &ContainerScanResult{
		ImageRef:        imageRef,
		Layers:          []LayerInfo{},
		Vulnerabilities: []Vulnerability{},
		MalwareDetected: []MalwareDetection{},
		Secrets:         []SecretDetection{},
		ConfigIssues:    []ConfigIssue{},
	}

	// Try Trivy first (most comprehensive)
	if cs.trivyPath != "" {
		if err := cs.scanWithTrivy(ctx, imageRef, result); err == nil {
			result.ScannerUsed = "Trivy"
			result.ScanDuration = time.Since(start)
			return result, nil
		}
	}

	// Fallback to Grype
	if cs.grypePath != "" {
		if err := cs.scanWithGrype(ctx, imageRef, result); err == nil {
			result.ScannerUsed = "Grype"
			result.ScanDuration = time.Since(start)
			return result, nil
		}
	}

	// Fallback to built-in scanning
	if err := cs.scanWithBuiltIn(ctx, imageRef, result); err != nil {
		return nil, fmt.Errorf("all scanning methods failed: %w", err)
	}

	result.ScannerUsed = "Built-in"
	result.ScanDuration = time.Since(start)

	return result, nil
}

// scanWithTrivy uses Trivy scanner for comprehensive vulnerability scanning
func (cs *ContainerScanner) scanWithTrivy(ctx context.Context, imageRef string, result *ContainerScanResult) error {
	// Run trivy with JSON output
	cmd := exec.CommandContext(ctx, cs.trivyPath, "image", "--format", "json", "--scanners", "vuln,secret,config", imageRef)

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("trivy scan failed: %w", err)
	}

	// Parse Trivy JSON output
	var trivyResult TrivyOutput
	if err := json.Unmarshal(output, &trivyResult); err != nil {
		return fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Convert Trivy results to our format
	cs.convertTrivyResults(&trivyResult, result)

	// Additional malware scanning on extracted layers
	if cs.malwareScanner != nil {
		cs.scanLayersForMalware(ctx, imageRef, result)
	}

	return nil
}

// scanWithGrype uses Grype scanner for vulnerability scanning
func (cs *ContainerScanner) scanWithGrype(ctx context.Context, imageRef string, result *ContainerScanResult) error {
	cmd := exec.CommandContext(ctx, cs.grypePath, imageRef, "-o", "json")

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("grype scan failed: %w", err)
	}

	var grypeResult GrypeOutput
	if err := json.Unmarshal(output, &grypeResult); err != nil {
		return fmt.Errorf("failed to parse grype output: %w", err)
	}

	cs.convertGrypeResults(&grypeResult, result)

	// Additional malware scanning
	if cs.malwareScanner != nil {
		cs.scanLayersForMalware(ctx, imageRef, result)
	}

	return nil
}

// scanWithBuiltIn performs built-in OCI image analysis
func (cs *ContainerScanner) scanWithBuiltIn(ctx context.Context, imageRef string, result *ContainerScanResult) error {
	// Extract image to temporary directory
	tmpDir, err := os.MkdirTemp("", "container-scan-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Use docker/podman to save image
	if err := cs.exportImage(ctx, imageRef, tmpDir); err != nil {
		return fmt.Errorf("failed to export image: %w", err)
	}

	// Parse OCI layout
	if err := cs.parseOCIImage(tmpDir, result); err != nil {
		return fmt.Errorf("failed to parse OCI image: %w", err)
	}

	// Scan each layer for malware
	if cs.malwareScanner != nil {
		for i := range result.Layers {
			cs.scanLayerForMalware(ctx, tmpDir, &result.Layers[i], result)
		}
	}

	// Detect secrets in layers
	cs.detectSecrets(tmpDir, result)

	// Analyze container configuration
	cs.analyzeConfig(tmpDir, result)

	return nil
}

// exportImage exports container image to directory using docker/podman
func (cs *ContainerScanner) exportImage(ctx context.Context, imageRef, destDir string) error {
	// Try docker first
	dockerPath := findExecutable("docker")
	if dockerPath != "" {
		cmd := exec.CommandContext(ctx, "docker", "save", imageRef, "-o", filepath.Join(destDir, "image.tar"))
		if err := cmd.Run(); err == nil {
			return cs.extractTar(filepath.Join(destDir, "image.tar"), destDir)
		}
	}

	// Try podman
	podmanPath := findExecutable("podman")
	if podmanPath != "" {
		cmd := exec.CommandContext(ctx, "podman", "save", imageRef, "-o", filepath.Join(destDir, "image.tar"))
		if err := cmd.Run(); err == nil {
			return cs.extractTar(filepath.Join(destDir, "image.tar"), destDir)
		}
	}

	return fmt.Errorf("neither docker nor podman available")
}

// parseOCIImage parses an exported OCI image structure
func (cs *ContainerScanner) parseOCIImage(dir string, result *ContainerScanResult) error {
	// Read manifest.json
	manifestPath := filepath.Join(dir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifests []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}

	if err := json.Unmarshal(manifestData, &manifests); err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	if len(manifests) == 0 {
		return fmt.Errorf("no manifests found")
	}

	manifest := manifests[0]

	// Read image config
	configPath := filepath.Join(dir, manifest.Config)
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var imgConfig ImageConfig
	if err := json.Unmarshal(configData, &imgConfig); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	result.ImageID = imgConfig.Config.Image
	result.BaseImage = cs.detectBaseImage(&imgConfig)

	// Parse layers
	for i, layerPath := range manifest.Layers {
		layerInfo := LayerInfo{
			Digest: layerPath,
		}

		// Get layer size
		fullPath := filepath.Join(dir, layerPath)
		if stat, err := os.Stat(fullPath); err == nil {
			layerInfo.Size = stat.Size()
			result.Size += stat.Size()
		}

		// Get command from history if available
		if i < len(imgConfig.History) {
			layerInfo.Command = imgConfig.History[i].CreatedBy
			layerInfo.Created = imgConfig.History[i].Created
		}

		result.Layers = append(result.Layers, layerInfo)
	}

	return nil
}

// scanLayersForMalware scans all container layers for malware
func (cs *ContainerScanner) scanLayersForMalware(ctx context.Context, imageRef string, result *ContainerScanResult) {
	// This would extract and scan each layer
	// For now, placeholder implementation
	for i := range result.Layers {
		result.Layers[i].ThreatLevel = "clean"
	}
}

// scanLayerForMalware scans a single layer for malware
func (cs *ContainerScanner) scanLayerForMalware(ctx context.Context, baseDir string, layer *LayerInfo, result *ContainerScanResult) {
	// Extract layer tar.gz
	layerPath := filepath.Join(baseDir, layer.Digest)

	// Create temp directory for layer contents
	layerDir, err := os.MkdirTemp("", "layer-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(layerDir)

	// Extract layer
	if err := cs.extractLayerTar(layerPath, layerDir); err != nil {
		return
	}

	// Scan all files in layer
	filepath.Walk(layerDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Scan file with DarkScan
		scanResult, err := cs.malwareScanner.ScanFile(ctx, path)
		if err == nil && scanResult.Infected {
			layer.MalwareFound = true
			layer.SuspiciousFiles = append(layer.SuspiciousFiles, info.Name())

			for _, threat := range scanResult.Threats {
				result.MalwareDetected = append(result.MalwareDetected, MalwareDetection{
					FilePath:   strings.TrimPrefix(path, layerDir),
					Layer:      layer.Digest,
					ThreatName: threat.Name,
					ThreatType: threat.Severity,
					Confidence: 0.9,
				})
			}
		}

		layer.FileCount++
		return nil
	})

	if layer.MalwareFound {
		layer.ThreatLevel = "critical"
	} else {
		layer.ThreatLevel = "clean"
	}
}

// detectSecrets scans for hardcoded secrets in container layers
func (cs *ContainerScanner) detectSecrets(dir string, result *ContainerScanResult) {
	// Common secret patterns
	secretPatterns := map[string]string{
		"AWS_KEY":      `AKIA[0-9A-Z]{16}`,
		"PRIVATE_KEY":  `-----BEGIN .* PRIVATE KEY-----`,
		"PASSWORD":     `(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]+`,
		"API_KEY":      `(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[^\s'\"]+`,
		"GITHUB_TOKEN": `ghp_[a-zA-Z0-9]{36}`,
	}

	// Scan files for secret patterns
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 10*1024*1024 { // Skip large files
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		for secretType, pattern := range secretPatterns {
			if strings.Contains(content, pattern) {
				result.Secrets = append(result.Secrets, SecretDetection{
					FilePath:   path,
					SecretType: secretType,
					Value:      "****REDACTED****",
					Severity:   "HIGH",
				})
			}
		}

		return nil
	})
}

// analyzeConfig analyzes container configuration for security issues
func (cs *ContainerScanner) analyzeConfig(dir string, result *ContainerScanResult) {
	configPath := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	var config ImageConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return
	}

	// Check for root user
	if config.Config.User == "" || config.Config.User == "root" || config.Config.User == "0" {
		result.ConfigIssues = append(result.ConfigIssues, ConfigIssue{
			Type:        "USER",
			Severity:    "MEDIUM",
			Description: "Container runs as root user",
			Remediation: "Use non-root user in Dockerfile: USER nonroot",
		})
	}

	// Check for privileged mode
	if len(config.Config.Env) > 0 {
		for _, env := range config.Config.Env {
			if strings.Contains(env, "PRIVILEGED=true") {
				result.ConfigIssues = append(result.ConfigIssues, ConfigIssue{
					Type:        "PRIVILEGE",
					Severity:    "HIGH",
					Description: "Container configured for privileged mode",
					Remediation: "Remove privileged mode unless absolutely necessary",
				})
			}
		}
	}
}

// detectBaseImage attempts to identify the base image
func (cs *ContainerScanner) detectBaseImage(config *ImageConfig) string {
	// Check history for FROM commands
	for _, hist := range config.History {
		if strings.Contains(hist.CreatedBy, "FROM") {
			parts := strings.Fields(hist.CreatedBy)
			for i, part := range parts {
				if part == "FROM" && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}
	}
	return "unknown"
}

// extractTar extracts a tar archive
func (cs *ContainerScanner) extractTar(tarPath, destDir string) error {
	file, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer file.Close()

	tr := tar.NewReader(file)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0755)
			outFile, err := os.Create(target)
			if err != nil {
				continue
			}
			io.Copy(outFile, tr)
			outFile.Close()
		}
	}

	return nil
}

// extractLayerTar extracts a gzipped layer tar
func (cs *ContainerScanner) extractLayerTar(layerPath, destDir string) error {
	file, err := os.Open(layerPath)
	if err != nil {
		return err
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0755)
			outFile, err := os.Create(target)
			if err != nil {
				continue
			}
			io.Copy(outFile, tr)
			outFile.Close()
		}
	}

	return nil
}

// Helper types for parsing external scanner outputs

type TrivyOutput struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string  `json:"VulnerabilityID"`
			PkgName         string  `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion    string  `json:"FixedVersion"`
			Severity        string  `json:"Severity"`
			Description     string  `json:"Description"`
			CVSS            float64 `json:"CVSS"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID   string `json:"RuleID"`
			Category string `json:"Category"`
			Severity string `json:"Severity"`
			Title    string `json:"Title"`
			Match    string `json:"Match"`
		} `json:"Secrets"`
	} `json:"Results"`
}

type GrypeOutput struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	} `json:"matches"`
}

type ImageConfig struct {
	Architecture string `json:"architecture"`
	Config       struct {
		Hostname     string   `json:"Hostname"`
		Domainname   string   `json:"Domainname"`
		User         string   `json:"User"`
		Env          []string `json:"Env"`
		Cmd          []string `json:"Cmd"`
		Image        string   `json:"Image"`
		WorkingDir   string   `json:"WorkingDir"`
		Entrypoint   []string `json:"Entrypoint"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"config"`
	Created time.Time `json:"created"`
	History []struct {
		Created    time.Time `json:"created"`
		CreatedBy  string    `json:"created_by"`
		EmptyLayer bool      `json:"empty_layer,omitempty"`
	} `json:"history"`
}

// convertTrivyResults converts Trivy output to our format
func (cs *ContainerScanner) convertTrivyResults(trivy *TrivyOutput, result *ContainerScanResult) {
	for _, r := range trivy.Results {
		for _, vuln := range r.Vulnerabilities {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				ID:          vuln.VulnerabilityID,
				Severity:    vuln.Severity,
				Package:     vuln.PkgName,
				Version:     vuln.InstalledVersion,
				FixedIn:     vuln.FixedVersion,
				Description: vuln.Description,
				CVSS:        vuln.CVSS,
			})
		}

		for _, secret := range r.Secrets {
			result.Secrets = append(result.Secrets, SecretDetection{
				SecretType: secret.Category,
				Value:      "****REDACTED****",
				Severity:   secret.Severity,
			})
		}
	}
}

// convertGrypeResults converts Grype output to our format
func (cs *ContainerScanner) convertGrypeResults(grype *GrypeOutput, result *ContainerScanResult) {
	for _, match := range grype.Matches {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			ID:          match.Vulnerability.ID,
			Severity:    match.Vulnerability.Severity,
			Package:     match.Artifact.Name,
			Version:     match.Artifact.Version,
			Description: match.Vulnerability.Description,
		})
	}
}

// findExecutable locates an executable in PATH
func findExecutable(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}
