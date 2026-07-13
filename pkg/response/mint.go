package response

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

type EndpointOwnerLookup interface {
	OrganizationForEndpoint(context.Context, string) (string, error)
}
type MintRequest struct {
	Role, TenantID, EndpointID string
	Action                     Action
}
type ActionMinter struct {
	key    ed25519.PrivateKey
	owners EndpointOwnerLookup
	ttl    time.Duration
	now    func() time.Time
}

func NewActionMinter(k ed25519.PrivateKey, o EndpointOwnerLookup, ttl time.Duration, now func() time.Time) *ActionMinter {
	return &ActionMinter{key: append(ed25519.PrivateKey(nil), k...), owners: o, ttl: ttl, now: now}
}

// Mint authorizes role, action, and live endpoint ownership before signing.
// Threats: cross-tenant and over-privileged remote actions are rejected; HTTP handlers cannot override signed audiences.
func (m *ActionMinter) Mint(ctx context.Context, r MintRequest) (string, error) {
	if len(m.key) != ed25519.PrivateKeySize || m.owners == nil || m.now == nil || m.ttl <= 0 || m.ttl > 5*time.Minute || r.TenantID == "" || r.EndpointID == "" || !roleAllows(r.Role, r.Action) {
		return "", fmt.Errorf("remote action is not authorized")
	}
	owner, err := m.owners.OrganizationForEndpoint(ctx, r.EndpointID)
	if err != nil {
		return "", fmt.Errorf("resolve endpoint ownership: %w", err)
	}
	if owner == "" || owner != r.TenantID {
		return "", fmt.Errorf("endpoint tenant mismatch")
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate command ID: %w", err)
	}
	return SignActionToken(m.key, ActionClaims{ID: hex.EncodeToString(id[:]), TenantID: r.TenantID, EndpointID: r.EndpointID, Action: r.Action, ExpiresAt: m.now().Add(m.ttl)})
}
func roleAllows(role string, a Action) bool {
	switch role {
	case "admin":
		return a == ActionKillProcess || a == ActionCollectFile || a == ActionReadMemory || a == ActionListPersistence
	case "security_operator":
		return a == ActionKillProcess || a == ActionCollectFile || a == ActionListPersistence
	}
	return false
}
