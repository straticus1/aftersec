package forensics

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"time"
)

type FlossResult struct {
	StaticStrings  []string `json:"static_strings"`
	DecodedStrings []string `json:"decoded_strings"`
	StackStrings   []string `json:"stack_strings"`
	TightStrings   []string `json:"tight_strings"`
}

// IsFlossInstalled checks if the Mandiant FLOSS binary is available in PATH
func IsFlossInstalled() bool {
	_, err := exec.LookPath("floss")
	return err == nil
}

// ExtractFLOSS executes Mandiant FLOSS against the target file.
// It parses the JSON output into a slice of structured decoded strings.
func ExtractFLOSS(ctx context.Context, path string) (*FlossResult, error) {
	// Execute 'floss -j <path>'
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "floss", "-j", "--no-static-strings", path)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	err := cmd.Run()
	if err != nil && outBuf.Len() == 0 {
		return nil, err
	}

	// Parse JSON
	var raw struct {
		Strings struct {
			DecodedStrings []string `json:"decoded_strings"`
			StackStrings   []string `json:"stack_strings"`
			TightStrings   []string `json:"tight_strings"`
		} `json:"strings"`
	}

	if err := json.Unmarshal(outBuf.Bytes(), &raw); err != nil {
		return nil, err
	}

	return &FlossResult{
		DecodedStrings: raw.Strings.DecodedStrings,
		StackStrings:   raw.Strings.StackStrings,
		TightStrings:   raw.Strings.TightStrings,
	}, nil
}
