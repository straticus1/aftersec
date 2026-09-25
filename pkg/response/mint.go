package response

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"aftersec/pkg/preserve"
)

type EndpointOwnerLookup interface {
	OrganizationForEndpoint(context.Context, string) (string, error)
}
type MintRequest struct {
	Role, TenantID, EndpointID string
	Action                     Action
	Arguments                  map[string]string
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
	return SignActionToken(m.key, ActionClaims{ID: hex.EncodeToString(id[:]), TenantID: r.TenantID, EndpointID: r.EndpointID, Action: r.Action, ExpiresAt: m.now().Add(m.ttl), Arguments: cloneArguments(r.Arguments)})
}
func roleAllows(role string, a Action) bool {
	switch role {
	case "admin":
		return a == ActionKillProcess || a == ActionCollectFile || a == ActionReadMemory || a == ActionListPersistence || a == ActionQuarantine || a == ActionReleaseQuarantine || a == ActionBreakGlass || a == ActionDisplayShot || a == ActionDisplayRecord || a == ActionMarkStolen || a == ActionClearStolen || a == ActionPreserve || a == ActionClearPreserve
	case "security_operator":
		return a == ActionKillProcess || a == ActionCollectFile || a == ActionListPersistence || a == ActionQuarantine || a == ActionReleaseQuarantine || a == ActionDisplayShot || a == ActionDisplayRecord || a == ActionMarkStolen || a == ActionClearStolen || a == ActionPreserve || a == ActionClearPreserve
	}
	return false
}

// MintDelivered re-sends a stolen mark that an operator already authorized.
// It is not an HTTP entry point and it refuses every other action.
func (m *ActionMinter) MintDelivered(ctx context.Context, tenant, endpoint string, action Action) (string, error) {
	if action != ActionMarkStolen && action != ActionClearStolen {
		return "", fmt.Errorf("remote action is not authorized")
	}
	if len(m.key) != ed25519.PrivateKeySize || m.owners == nil || m.now == nil || m.ttl <= 0 || m.ttl > 5*time.Minute || tenant == "" || endpoint == "" {
		return "", fmt.Errorf("remote action is not authorized")
	}
	owner, err := m.owners.OrganizationForEndpoint(ctx, endpoint)
	if err != nil {
		return "", fmt.Errorf("resolve endpoint ownership: %w", err)
	}
	if owner == "" || owner != tenant {
		return "", fmt.Errorf("endpoint tenant mismatch")
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate command ID: %w", err)
	}
	return SignActionToken(m.key, ActionClaims{ID: hex.EncodeToString(id[:]), TenantID: tenant, EndpointID: endpoint, Action: action, ExpiresAt: m.now().Add(m.ttl)})
}

// MintPreserve re-sends a preserve mark that an operator already recorded.
// The incident id and reason come from the server registry, not from the client.
func (m *ActionMinter) MintPreserve(ctx context.Context, tenant, endpoint, reason, incident string) (string, error) {
	args := map[string]string{"incident_id": incident, "reason": reason}
	if _, _, err := preserve.ParseMark(args); err != nil {
		return "", fmt.Errorf("remote action is not authorized")
	}
	if len(m.key) != ed25519.PrivateKeySize || m.owners == nil || m.now == nil || m.ttl <= 0 || m.ttl > 5*time.Minute || tenant == "" || endpoint == "" {
		return "", fmt.Errorf("remote action is not authorized")
	}
	owner, err := m.owners.OrganizationForEndpoint(ctx, endpoint)
	if err != nil {
		return "", fmt.Errorf("resolve endpoint ownership: %w", err)
	}
	if owner == "" || owner != tenant {
		return "", fmt.Errorf("endpoint tenant mismatch")
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("generate command ID: %w", err)
	}
	return SignActionToken(m.key, ActionClaims{ID: hex.EncodeToString(id[:]), TenantID: tenant, EndpointID: endpoint, Action: ActionPreserve, ExpiresAt: m.now().Add(m.ttl), Arguments: args})
}
