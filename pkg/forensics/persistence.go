package forensics

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type PersistenceFinding struct {
	PlistPath   string
	Program     string
	IsHidden    bool
	Authority   string
	ThreatScore ThreatScore
	Reason      string
}

// ScanPersistenceMechanisms parses all active macOS autostart locations and 
// flags any Plists pointing to hidden or temporary locations.
func ScanPersistenceMechanisms() ([]PersistenceFinding, error) {
	var findings []PersistenceFinding
	
	home, _ := os.UserHomeDir()
	dirs := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/System/Library/LaunchDaemons", // Read-only but good to scan
		"/System/Library/LaunchAgents",
		filepath.Join(home, "Library/LaunchAgents"),
	}

	for _, dir := range dirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".plist") {
				continue
			}
			
			fullPath := filepath.Join(dir, file.Name())
			
			// plutil neatly converts ugly binary/xml plists into uniform JSON
			out, err := exec.Command("plutil", "-convert", "json", "-o", "-", fullPath).Output()
			if err != nil {
				continue
			}
			
			var data map[string]interface{}
			if err := json.Unmarshal(out, &data); err != nil {
				continue
			}
			
			var program string
			if p, ok := data["Program"].(string); ok && p != "" {
				program = p
			} else if argsObj, ok := data["ProgramArguments"].([]interface{}); ok && len(argsObj) > 0 {
				if argStr, ok := argsObj[0].(string); ok {
					program = argStr
				}
			}
			
			if program == "" {
				continue
			}
			
			score := Safe
			var reasons []string
			
			isHidden := strings.Contains(program, "/.") || strings.HasPrefix(program, ".")
			if isHidden {
				score = Suspicious
				reasons = append(reasons, "Binary runs from a hidden directory/file path")
			}
			
			if strings.HasPrefix(program, "/tmp") || strings.HasPrefix(program, "/var/tmp") {
				score = Malicious
				reasons = append(reasons, "Persistent payload runs from volatile temporary space")
			}
			
			sigInfo, err := VerifySignature(program)
			var authority string
			if err == nil {
				if sigInfo.Valid {
					authority = sigInfo.Authority
					if sigInfo.TeamID == "" && !strings.Contains(sigInfo.Authority, "Software Signing") {
						// Ad-hoc signed or non-standard Apple signature without TeamID
						if score < Suspicious {
							score = Suspicious
						}
						reasons = append(reasons, "Binary is ad-hoc signed or lacks a valid Team ID")
					}
				} else {
					authority = "Unsigned"
					if score < Suspicious {
						score = Suspicious
					}
					reasons = append(reasons, "Binary is completely unsigned")
				}
			} else {
				authority = "Unknown (Error checking signature)"
			}

			if score > Safe {
				findings = append(findings, PersistenceFinding{
					PlistPath:   fullPath,
					Program:     program,
					IsHidden:    isHidden,
					Authority:   authority,
					ThreatScore: score,
					Reason:      strings.Join(reasons, "; "),
				})
			}
		}
	}
	
	return findings, nil
}
