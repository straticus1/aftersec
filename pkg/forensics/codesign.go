package forensics

import (
	"bytes"
	"os/exec"
	"strings"
)

// SignatureInfo holds the parsed code signature details.
type SignatureInfo struct {
	Valid     bool
	Authority string
	TeamID    string
}

// VerifySignature uses the macOS `codesign` utility to verify a Mach-O binary.
func VerifySignature(filePath string) (SignatureInfo, error) {
	var info SignatureInfo

	// -dv --verbose=4 outputs to stderr
	cmd := exec.Command("codesign", "-dv", filePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stderr.String()

	// If codesign fails, it might be unsigned or structurally invalid
	if err != nil {
		if strings.Contains(output, "code object is not signed at all") ||
			strings.Contains(output, "invalid signature") ||
			strings.Contains(output, "not valid") {
			info.Valid = false
			return info, nil
		}
		// Some other error (e.g., file doesn't exist, permission denied)
		return info, err
	}

	info.Valid = true

	// Parse Authority and TeamIdentifier
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Authority=") {
			// Get the first authority (the certificate that signed it)
			if info.Authority == "" {
				info.Authority = strings.TrimPrefix(line, "Authority=")
			}
		} else if strings.HasPrefix(line, "TeamIdentifier=") {
			info.TeamID = strings.TrimPrefix(line, "TeamIdentifier=")
		}
	}

	return info, nil
}
