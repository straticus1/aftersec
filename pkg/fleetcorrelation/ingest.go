package fleetcorrelation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// FromTelemetry reads one synced client payload. A payload without a fleet
// claim is ignored. A claimed file hash or fingerprint that is not 64
// lowercase hex digits is rejected.
//
// Threats: credential values must already be fingerprints. This parser does
// not accept raw secrets, and a malformed claim is not treated as absent.
func FromTelemetry(tenant, endpoint, eventType, payload string, at time.Time) (Event, bool, error) {
	if payload == "" {
		return Event{}, false, nil
	}
	var body struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"`
		Value    string `json:"value"`
		Path     string `json:"path"`
		Identity struct {
			SHA256 string `json:"SHA256"`
		} `json:"identity"`
	}
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		if !isFleetKind(Kind(eventType)) {
			return Event{}, false, nil
		}
		return Event{}, false, ErrInvalidEvent
	}
	if body.Identity.SHA256 != "" {
		if tenant == "" || endpoint == "" || body.Path == "" || at.IsZero() || !hex64(body.Identity.SHA256) {
			return Event{}, false, ErrInvalidEvent
		}
		sum := sha256.Sum256([]byte(tenant + "\x00" + endpoint + "\x00" + body.Identity.SHA256 + "\x00" + at.UTC().Format(time.RFC3339Nano)))
		return Event{
			ID: hex.EncodeToString(sum[:]), TenantID: tenant, EndpointID: endpoint,
			Kind: FileHash, Value: body.Identity.SHA256, At: at.UTC(),
		}, true, nil
	}
	kind := Kind(body.Kind)
	if kind == "" {
		kind = Kind(eventType)
	}
	if !isFleetKind(kind) {
		return Event{}, false, nil
	}
	if tenant == "" || endpoint == "" || body.ID == "" || at.IsZero() || len(body.ID) > 128 || !validValue(kind, body.Value) {
		return Event{}, false, ErrInvalidEvent
	}
	return Event{ID: body.ID, TenantID: tenant, EndpointID: endpoint, Kind: kind, Value: body.Value, At: at.UTC()}, true, nil
}

func isFleetKind(kind Kind) bool {
	return kind == FileHash || kind == SSHLogin || kind == CredentialUse
}

func validValue(kind Kind, value string) bool {
	switch kind {
	case FileHash, CredentialUse:
		return hex64(value)
	case SSHLogin:
		return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n")
	default:
		return false
	}
}

func hex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
