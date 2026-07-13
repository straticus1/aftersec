//go:build linux

package client

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type KeyringCredentialStore struct {
	directory  string
	hardwareID string
}

func newProductionCredentialStore(directory, hardwareID string) (CredentialStore, error) {
	return &KeyringCredentialStore{directory: directory, hardwareID: hardwareID}, nil
}

func (s *KeyringCredentialStore) Save(certificate []byte, refreshToken string) error {
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
	description := "aftersec:refresh:" + s.hardwareID
	if existing, err := unix.KeyctlSearch(unix.KEY_SPEC_USER_KEYRING, "user", description, 0); err == nil {
		if _, err := unix.KeyctlBuffer(unix.KEYCTL_UPDATE, existing, []byte(refreshToken), 0); err != nil {
			return fmt.Errorf("update refresh token in kernel keyring: %w", err)
		}
		return nil
	}
	if _, err := unix.AddKey("user", description, []byte(refreshToken), unix.KEY_SPEC_USER_KEYRING); err != nil {
		return fmt.Errorf("store refresh token in kernel keyring: %w", err)
	}
	return nil
}
