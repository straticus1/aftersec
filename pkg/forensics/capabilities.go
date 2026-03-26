package forensics

import (
	"archive/zip"
	"debug/macho"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Capability defines a discovered software capability
type Capability struct {
	Name        string
	Description string
	Category    string
	RiskLevel   ThreatScore
}

// CapabilitiesReport represents the deep analysis of a binary or .app bundle
type CapabilitiesReport struct {
	Path         string
	IsAppBundle  bool
	Entropy      float64
	IsPacked     bool
	Capabilities []Capability
	Imports      []string
	ThreatScore  ThreatScore
}

var CapabilityMatrix = []struct {
	ImportMatch string // Substring to match in imported library/symbol
	Capability  Capability
}{
	{"CFNetwork", Capability{"Network Comms", "Uses Apple CFNetwork for web/network communication", "Network", Suspicious}},
	{"CommonCrypto", Capability{"Cryptography", "Uses CommonCrypto for encryption/hashing", "Crypto", Safe}},
	{"CGEventTapCreate", Capability{"Keylogging/Screen Scraping", "Uses CoreGraphics Event Taps which can intercept keystrokes", "Surveillance", Malicious}},
	{"ptrace", Capability{"Anti-Debugging", "Uses ptrace (potentially PT_DENY_ATTACH) to evade debuggers", "Evasion", Malicious}},
	{"sysctl", Capability{"System Fingerprinting", "Uses sysctl to gather deep system hardware/OS information", "Reconnaissance", Suspicious}},
	{"Security", Capability{"Keychain Access", "Accesses the macOS Keychain or Security frameworks", "Credentials", Safe}},
	{"AVFoundation", Capability{"Camera/Microphone Access", "Can access audio or video capture devices", "Surveillance", Suspicious}},
	{"NSWorkspace", Capability{"Process Manipulation", "Can launch or manipulate other processes and workspace states", "Execution", Suspicious}},
	{"FSEvents", Capability{"Filesystem Monitoring", "Monitors the entire filesystem for changes in real-time", "Surveillance", Suspicious}},
	{"AppKit", Capability{"GUI Application", "Standard graphical macOS application", "Interface", Safe}},
	{"libcurl", Capability{"Network Comms", "Uses libcurl for networking", "Network", Suspicious}},
}

// CalculateEntropy measures the Shannon entropy of a file, returning 0.0-8.0
func CalculateEntropy(path string) (float64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	counts := make([]int64, 256)
	var total int64

	buf := make([]byte, 8192)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				counts[buf[i]]++
			}
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}

	if total == 0 {
		return 0, nil
	}

	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}
	return entropy, nil
}

// AnalyzeBinary parses a single Mach-O binary and extracts its capabilities
func AnalyzeBinary(path string) (*CapabilitiesReport, error) {
	report := &CapabilitiesReport{
		Path: path,
		ThreatScore: Safe,
	}

	// Calculate Entropy
	ent, err := CalculateEntropy(path)
	if err == nil {
		report.Entropy = ent
		if ent > 7.2 {
			report.IsPacked = true
			if report.ThreatScore < Suspicious {
				report.ThreatScore = Suspicious
			}
		}
	}

	// Safely open the Mach-O file. Provide support for fat (universal) binaries.
	var importedLibs []string
	var importedSyms []string

	fat, err := macho.OpenFat(path)
	if err == nil {
		defer fat.Close()
		// Just parse the first architecture to grab imports since they're usually mirrored
		if len(fat.Arches) > 0 {
			libs, _ := fat.Arches[0].ImportedLibraries()
			importedLibs = append(importedLibs, libs...)
			syms, _ := fat.Arches[0].ImportedSymbols()
			importedSyms = append(importedSyms, syms...)
		}
	} else {
		// Try normal Mach-O
		mo, err := macho.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to parse macho file: %w", err)
		}
		defer mo.Close()
		libs, _ := mo.ImportedLibraries()
		importedLibs = append(importedLibs, libs...)
		syms, _ := mo.ImportedSymbols()
		importedSyms = append(importedSyms, syms...)
	}

	// Combine lines and search capability mapping
	allImports := append(importedLibs, importedSyms...)
	report.Imports = allImports

	capMap := make(map[string]bool)

	for _, imp := range allImports {
		for _, mapped := range CapabilityMatrix {
			if strings.Contains(imp, mapped.ImportMatch) {
				if !capMap[mapped.Capability.Name] {
					capMap[mapped.Capability.Name] = true
					report.Capabilities = append(report.Capabilities, mapped.Capability)
					
					if mapped.Capability.RiskLevel > report.ThreatScore {
						report.ThreatScore = mapped.Capability.RiskLevel
					}
				}
			}
		}
	}

	// Simple string extraction for IPv4 addresses and URLs (Naive Approach)
	// We read the first MB of the file to avoid memory explosion
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		head := make([]byte, 1024*1024)
		n, _ := f.Read(head)
		if n > 0 {
			s := string(head[:n])
			if strings.Contains(s, "http://") || strings.Contains(s, "https://") {
				if !capMap["Embedded URLs"] {
					report.Capabilities = append(report.Capabilities, Capability{"Embedded URLs", "Contains hardcoded HTTP/HTTPS URLs", "Network", Suspicious})
					if report.ThreatScore < Suspicious {
						report.ThreatScore = Suspicious
					}
				}
			}
			if strings.Contains(s, "192.168.") || strings.Contains(s, "10.") || strings.Contains(s, "172.") {
				// internal IPs
			} else if strings.Contains(s, "Mining") || strings.Contains(s, "cryptonight") {
				report.Capabilities = append(report.Capabilities, Capability{"Cryptomining", "Contains references to cryptocurrency mining", "Malware", Malicious})
				report.ThreatScore = Malicious
			}
		}
	}

	return report, nil
}

// AnalyzeAppBundle parses an entire .app container and its embedded Mach-O binaries
func AnalyzeAppBundle(appPath string) (*CapabilitiesReport, error) {
	report := &CapabilitiesReport{
		Path:        appPath,
		IsAppBundle: true,
		ThreatScore: Safe,
	}

	infoPlist := filepath.Join(appPath, "Contents", "Info.plist")
	
	mainExec := ""
	// Use plutil to convert Info.plist to JSON
	out, err := exec.Command("plutil", "-convert", "json", "-o", "-", infoPlist).Output()
	if err == nil {
		var data map[string]interface{}
		if err := json.Unmarshal(out, &data); err == nil {
			if execName, ok := data["CFBundleExecutable"].(string); ok {
				mainExec = execName
			}
		}
	}

	// Target directories in a standard macOS app bundle
	searchDirs := []string{
		filepath.Join(appPath, "Contents", "MacOS"),
		filepath.Join(appPath, "Contents", "Frameworks"),
		filepath.Join(appPath, "Contents", "XPCServices"),
	}

	capMap := make(map[string]bool)

	for _, dir := range searchDirs {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			
			// Try to parse every file as a Mach-O. If it fails, ignore.
			subReport, err := AnalyzeBinary(path)
			if err != nil {
				return nil // It's not a mach-o or we can't parse it
			}

			// Aggregate capabilities
			for _, c := range subReport.Capabilities {
				if !capMap[c.Name] {
					capMap[c.Name] = true
					report.Capabilities = append(report.Capabilities, c)
				}
			}

			// Keep highest threat score
			if subReport.ThreatScore > report.ThreatScore {
				report.ThreatScore = subReport.ThreatScore
			}

			// If it's the main executable, reflect its entropy and packed status to the bundle as a whole
			if mainExec != "" && info.Name() == mainExec {
				report.Entropy = subReport.Entropy
				report.IsPacked = subReport.IsPacked
			}

			return nil
		})
	}

	return report, nil
}

// AnalyzePDF parses a PDF document for embedded malicious markers like JavaScript or Launch actions
func AnalyzePDF(path string) (*CapabilitiesReport, error) {
	report := &CapabilitiesReport{
		Path:        path,
		ThreatScore: Safe,
	}

	ent, err := CalculateEntropy(path)
	if err == nil {
		report.Entropy = ent
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read small chunk just for magic and simple string matching
	head := make([]byte, 1024*1024)
	n, _ := f.Read(head)
	s := string(head[:n])

	capMap := make(map[string]bool)

	indicators := []struct {
		Keywords []string
		Threat   Capability
	}{
		{[]string{"/JS ", "/JavaScript ", "/JS\r", "/JavaScript\r", "/JS\n", "/JavaScript\n"}, Capability{"Embedded JavaScript", "Contains embedded AcroJS for dynamic execution", "Execution", Suspicious}},
		{[]string{"/Launch ", "/OpenAction ", "/Launch\r", "/OpenAction\r", "/Launch\n", "/OpenAction\n"}, Capability{"Auto-Execution", "Contains actions that execute automatically upon opening", "Execution", Malicious}},
		{[]string{"/EmbeddedFiles "}, Capability{"Embedded Objects", "Contains embedded files which could be payloads", "Persistence", Suspicious}},
	}

	for _, ind := range indicators {
		for _, kw := range ind.Keywords {
			if strings.Contains(s, kw) && !capMap[ind.Threat.Name] {
				capMap[ind.Threat.Name] = true
				report.Capabilities = append(report.Capabilities, ind.Threat)
				if ind.Threat.RiskLevel > report.ThreatScore {
					report.ThreatScore = ind.Threat.RiskLevel
				}
			}
		}
	}

	return report, nil
}

// AnalyzeOfficeOOXML parses modern zip-based Office documents (.docx, .xlsx, .pptm)
func AnalyzeOfficeOOXML(path string) (*CapabilitiesReport, error) {
	report := &CapabilitiesReport{
		Path:        path,
		ThreatScore: Safe,
	}

	ent, err := CalculateEntropy(path)
	if err == nil {
		report.Entropy = ent
	}

	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	hasMacros := false
	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), "vbaproject.bin") {
			hasMacros = true
			
			rc, err := f.Open()
			if err == nil {
				buf := make([]byte, 1024*1024)
				n, _ := rc.Read(buf)
				rc.Close()
				s := string(buf[:n])
				
				if strings.Contains(s, "AutoOpen") || strings.Contains(s, "Document_Open") || strings.Contains(s, "Workbook_Open") {
					report.Capabilities = append(report.Capabilities, Capability{"Macro Auto-Execution", "Contains VBA macros that execute automatically", "Execution", Malicious})
					report.ThreatScore = Malicious
				}
				if strings.Contains(s, "CreateObject") || strings.Contains(s, "WScript.Shell") || strings.Contains(s, "Shell") {
					report.Capabilities = append(report.Capabilities, Capability{"Macro Shell Execution", "VBA macro attempts to execute OS commands or drop objects", "Execution", Malicious})
					report.ThreatScore = Malicious
				}
			}
		}
	}

	if hasMacros {
		report.Capabilities = append(report.Capabilities, Capability{"VBA Macros", "Document contains embedded VBA macros", "Execution", Suspicious})
		if report.ThreatScore < Suspicious {
			report.ThreatScore = Suspicious
		}
	}

	return report, nil
}

// AnalyzeOfficeOLE parses legacy Office documents looking for OLE string indicators
func AnalyzeOfficeOLE(path string) (*CapabilitiesReport, error) {
	report := &CapabilitiesReport{
		Path:        path,
		ThreatScore: Safe,
	}

	ent, err := CalculateEntropy(path)
	if err == nil {
		report.Entropy = ent
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	head := make([]byte, 2*1024*1024)
	n, _ := f.Read(head)
	s := string(head[:n])

	if strings.Contains(s, "AutoOpen") || strings.Contains(s, "Document_Open") || strings.Contains(s, "Workbook_Open") {
		report.Capabilities = append(report.Capabilities, Capability{"Macro Auto-Execution", "Contains VBA macros that execute automatically", "Execution", Malicious})
		report.ThreatScore = Malicious
	}
	if strings.Contains(s, "CreateObject") || strings.Contains(s, "WScript.Shell") {
		report.Capabilities = append(report.Capabilities, Capability{"Macro Shell Execution", "VBA macro attempts to execute OS commands or drop objects", "Execution", Malicious})
		report.ThreatScore = Malicious
	}

	return report, nil
}

// AnalyzePath determines if the path is an .app bundle, document, or a raw binary and routes accordingly
func AnalyzePath(path string) (*CapabilitiesReport, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".app") {
		return AnalyzeAppBundle(path)
	}

	lowerPath := strings.ToLower(path)
	if strings.HasSuffix(lowerPath, ".pdf") {
		return AnalyzePDF(path)
	}
	if strings.HasSuffix(lowerPath, ".docx") || strings.HasSuffix(lowerPath, ".xlsx") || strings.HasSuffix(lowerPath, ".pptm") || strings.HasSuffix(lowerPath, ".docm") || strings.HasSuffix(lowerPath, ".xlsm") || strings.HasSuffix(lowerPath, ".pptm") {
		return AnalyzeOfficeOOXML(path)
	}
	if strings.HasSuffix(lowerPath, ".doc") || strings.HasSuffix(lowerPath, ".xls") || strings.HasSuffix(lowerPath, ".ppt") {
		return AnalyzeOfficeOLE(path)
	}

	// Dynamic magic byte fallback
	f, err := os.Open(path)
	if err == nil {
		magic := make([]byte, 8)
		f.Read(magic)
		f.Close()
		
		if string(magic[:4]) == "%PDF" {
			return AnalyzePDF(path)
		}
		
		if magic[0] == 0xD0 && magic[1] == 0xCF && magic[2] == 0x11 && magic[3] == 0xE0 && magic[4] == 0xA1 && magic[5] == 0xB1 && magic[6] == 0x1A && magic[7] == 0xE1 {
			return AnalyzeOfficeOLE(path)
		}
	}

	return AnalyzeBinary(path)
}
