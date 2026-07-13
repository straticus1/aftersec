//go:build !darwin && !linux

package client

import "fmt"

func newProductionCredentialStore(_, _ string) (CredentialStore, error) {
	return nil, fmt.Errorf("production credential storage is unsupported on this platform")
}
