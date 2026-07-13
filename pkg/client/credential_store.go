package client

import "fmt"

func NewPlatformCredentialStore(mode, directory, hardwareID string) (CredentialStore, error) {
	if mode == "development" {
		return NewFileCredentialStore(directory, mode), nil
	}
	if mode != "production" {
		return nil, fmt.Errorf("credential mode must be explicitly production or development")
	}
	if directory == "" || hardwareID == "" {
		return nil, fmt.Errorf("credential directory and hardware ID are required")
	}
	return newProductionCredentialStore(directory, hardwareID)
}
