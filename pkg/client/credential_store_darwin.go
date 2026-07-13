//go:build darwin

package client

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// KeychainCredentialStore stores refresh credentials in the macOS login
// Keychain. The secret is supplied over stdin and never appears in argv.
type KeychainCredentialStore struct {
	directory  string
	hardwareID string
}

func newProductionCredentialStore(directory, hardwareID string) (CredentialStore, error) {
	return &KeychainCredentialStore{directory: directory, hardwareID: hardwareID}, nil
}

func (s *KeychainCredentialStore) Save(certificate []byte, refreshToken string) error {
	if len(certificate) == 0 || refreshToken == "" {
		return fmt.Errorf("certificate and refresh token are required")
	}
	if err := os.MkdirAll(s.directory, 0700); err != nil {
		return err
	}
	if err := os.Chmod(s.directory, 0700); err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(s.directory, "client.crt"), certificate); err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-U", "-a", s.hardwareID, "-s", "com.aftersec.refresh-token", "-w")
	cmd.Stdin = strings.NewReader(refreshToken + "\n")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("store refresh token in Keychain: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}
