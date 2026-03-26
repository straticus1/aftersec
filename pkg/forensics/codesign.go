package forensics

import (
	"bytes"
	"context"
	"fmt"
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

// AppSignatureResult holds the cryptographic health of a macOS application bundle
type AppSignatureResult struct {
	IsValid     bool
	IsAdHoc     bool
	TeamID      string
	Authority   string
	Issues      []string
	RawOutput   string
}

// VerifyMacBundle runs Apple's native codesign and spctl tools against an .app bundle
// to strictly determine if its cryptographic seal is unbroken and if it is signed by a valid developer.
func VerifyMacBundle(ctx context.Context, appPath string) (*AppSignatureResult, error) {
	res := &AppSignatureResult{
		IsValid: false,
		Issues:  []string{},
	}

	// Step 1: Deep Cryptographic Seal Verification
	cmd := exec.CommandContext(ctx, "codesign", "--verify", "--deep", "--strict", "--verbose=4", appPath)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	output := stderr.String() + out.String()
	res.RawOutput = output

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.Issues = append(res.Issues, "Cryptographic verification timed out (exceeded deadline). The application bundle is too massive or complex to verify safely.")
			return res, nil
		}
		res.Issues = append(res.Issues, fmt.Sprintf("Cryptographic Seal Broken: %v", err))
		res.Issues = append(res.Issues, "The application bundle has been structurally modified since the developer signed it. This is highly indicative of Dylib Hijacking or malware patching.")
		return res, nil
	}

	res.IsValid = true

	// Parse verbose output for metadata
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Authority=") {
			auth := strings.TrimPrefix(line, "Authority=")
			if res.Authority == "" {
				res.Authority = auth
			}
		}
		if strings.Contains(line, "TeamIdentifier=") {
			res.TeamID = strings.TrimPrefix(line, "TeamIdentifier=")
		}
	}

	// Ad-Hoc Signatures (Signed locally without a valid Apple Developer Certificate)
	if res.Authority == "" || strings.Contains(strings.ToLower(output), "ad hoc") {
		res.IsAdHoc = true
		res.IsValid = false
		res.Issues = append(res.Issues, "Ad-Hoc Signature Detected: The binary is structurally intact, but lacks a cryptographic chain-of-trust to Apple. It was likely compiled locally via Xcode or signed by an anonymous open-source stripping tool.")
		return res, nil
	}

	// Step 2: Apple Gatekeeper / Notarization Check (spctl)
	spctlCmd := exec.CommandContext(ctx, "spctl", "-a", "-t", "exec", "-vv", appPath)
	var spctlOut bytes.Buffer
	var spctlErr bytes.Buffer
	spctlCmd.Stdout = &spctlOut
	spctlCmd.Stderr = &spctlErr

	if err := spctlCmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.Issues = append(res.Issues, "Gatekeeper validation timed out (exceeded deadline).")
			res.IsValid = false
			return res, nil
		}
		combined := spctlOut.String() + spctlErr.String()
		res.Issues = append(res.Issues, fmt.Sprintf("Gatekeeper Rejection: %v", err))
		res.Issues = append(res.Issues, fmt.Sprintf("spctl output: %s", combined))
		res.IsValid = false 
		return res, nil
	}

	return res, nil
}
