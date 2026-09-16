package darkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type rotationFile struct {
	Credentials
	RotationID string `json:"rotation_id"`
}

func writePrivate(path string, value any, exclusive bool) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if exclusive {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if err = secureCredentialFile(path); err != nil {
			return err
		}
		if _, err = f.Write(data); err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			return err
		}
		return syncCredentialDirectory(path)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".aftersec-credentials-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = secureCredentialFile(f.Name()); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return replaceCredential(f.Name(), path)
}

// RotateCredentials is restart-safe: a pending credential is synced before the
// server invalidates the old key. Restart the daemon to load the new credential.
func RotateCredentials(ctx context.Context, path string) error {
	return rotateCredentials(ctx, path, true)
}
func rotateCredentials(ctx context.Context, path string, recoverExpired bool) error {
	current, err := Load(path)
	if err != nil {
		return err
	}
	pendingPath := path + ".rotation"
	pendingClient, err := Load(pendingPath)
	var pending rotationFile
	if os.IsNotExist(err) {
		var response struct {
			RotationID string `json:"rotation_id"`
			APIKey     string `json:"api_key"`
			DeviceID   string `json:"device_id"`
			App        string `json:"app"`
		}
		if err = current.request(ctx, "POST", "/api/v1/endpoints/aftersec/credential-rotations", map[string]any{}, &response, true); err != nil {
			return err
		}
		if response.DeviceID != current.DeviceID() || response.App != "aftersec" || response.APIKey == "" || len(response.RotationID) != 36 {
			return fmt.Errorf("rotation identity mismatch")
		}
		pending = rotationFile{Credentials: current.credentials, RotationID: response.RotationID}
		pending.APIKey = response.APIKey
		if err = writePrivate(pendingPath, pending, true); err != nil {
			return fmt.Errorf("old credential remains active; could not save rotation: %w", err)
		}
		pendingClient, err = New(pending.Credentials)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		raw, err := os.ReadFile(pendingPath)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &pending); err != nil {
			return err
		}
	}
	if pending.DeviceID != current.DeviceID() || pending.BaseURL != current.credentials.BaseURL || pending.RotationID == "" {
		return fmt.Errorf("pending rotation belongs to another endpoint")
	}
	var result struct {
		Success  bool   `json:"success"`
		DeviceID string `json:"device_id"`
	}
	if err = pendingClient.request(ctx, "POST", "/api/v1/endpoints/aftersec/credential-rotations/confirm", map[string]string{"rotation_id": pending.RotationID}, &result, true); err != nil {
		var apiErr *APIError
		if recoverExpired && errors.As(err, &apiErr) && (apiErr.Status == 401 || apiErr.Status == 409) && current.Heartbeat(ctx) == nil {
			if removeErr := os.Remove(pendingPath); removeErr != nil {
				return removeErr
			}
			if syncErr := syncCredentialDirectory(path); syncErr != nil {
				return syncErr
			}
			return rotateCredentials(ctx, path, false)
		}
		return fmt.Errorf("rotation not confirmed; pending file retained: %w", err)
	}
	if !result.Success || result.DeviceID != current.DeviceID() {
		return fmt.Errorf("rotation acknowledgment mismatch")
	}
	if err = writePrivate(path, pending.Credentials, false); err != nil {
		return fmt.Errorf("new key is active; rerun rotation to recover pending credential: %w", err)
	}
	if err = os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncCredentialDirectory(path)
}
