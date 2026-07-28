//go:build darwin

package binaryauth

import (
	"fmt"

	"aftersec/pkg/forensics"
)

func platformProvenance(path string) (string, string, error) {
	signature, err := forensics.VerifySignature(path)
	if err != nil {
		return "", "", fmt.Errorf("collect code-signing identity: %w", err)
	}
	if !signature.Valid {
		return "", "", nil
	}
	return signature.TeamID, signature.Authority, nil
}
