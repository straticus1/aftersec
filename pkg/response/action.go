package response

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type Action string

const (
	ActionKillProcess     Action = "kill_process"
	ActionCollectFile     Action = "collect_file"
	ActionReadMemory      Action = "read_memory"
	ActionListPersistence Action = "list_persistence"
	ActionQuarantine      Action = "quarantine"
	ActionReleaseQuarantine Action = "release_quarantine"
)

type ActionClaims struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	EndpointID string    `json:"endpoint_id"`
	Action     Action    `json:"action"`
	ExpiresAt  time.Time `json:"expires_at"`
	Arguments  map[string]string `json:"arguments,omitempty"`
}
type signedAction struct {
	Claims    json.RawMessage `json:"claims"`
	Signature string          `json:"signature"`
}

// SignActionToken signs a narrow endpoint/action audience with Ed25519.
func SignActionToken(key ed25519.PrivateKey, claims ActionClaims) (string, error) {
	if len(key) != ed25519.PrivateKeySize || !validClaims(claims) {
		return "", fmt.Errorf("valid signing key and action claims are required")
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	wire, err := json.Marshal(signedAction{Claims: body, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, body))})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(wire), nil
}

type ActionRunner interface {
	Run(context.Context, Action, map[string]string) ([]byte, error)
}
type ActionExecutor struct {
	mu               sync.Mutex
	key              ed25519.PublicKey
	tenant, endpoint string
	runner           ActionRunner
	max              int
	now              func() time.Time
	used             map[string]struct{}
}

func NewActionExecutor(key ed25519.PublicKey, tenant, endpoint string, runner ActionRunner, max int, now func() time.Time) *ActionExecutor {
	return &ActionExecutor{key: append(ed25519.PublicKey(nil), key...), tenant: tenant, endpoint: endpoint, runner: runner, max: max, now: now, used: map[string]struct{}{}}
}

// Execute verifies signature, audience, expiry, replay, and bounded output before returning data.
// Threats: forged/cross-tenant/replayed insider actions are denied. The runner remains responsible for OS authorization.
func (e *ActionExecutor) Execute(ctx context.Context, token string, args map[string]string) ([]byte, error) {
	if len(token) > 16*1024 || len(e.key) != ed25519.PublicKeySize || e.runner == nil || e.max <= 0 || e.now == nil {
		return nil, fmt.Errorf("remote action executor is not safely configured")
	}
	wire, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("decode action token")
	}
	var signed signedAction
	if json.Unmarshal(wire, &signed) != nil {
		return nil, fmt.Errorf("decode action token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(e.key, signed.Claims, sig) {
		return nil, fmt.Errorf("invalid action signature")
	}
	var c ActionClaims
	if json.Unmarshal(signed.Claims, &c) != nil || !validClaims(c) || c.TenantID != e.tenant || c.EndpointID != e.endpoint || !e.now().Before(c.ExpiresAt) {
		return nil, fmt.Errorf("action claims rejected")
	}
	e.mu.Lock()
	if _, ok := e.used[c.ID]; ok {
		e.mu.Unlock()
		return nil, fmt.Errorf("action replay rejected")
	}
	e.used[c.ID] = struct{}{}
	e.mu.Unlock()
	// Arguments are part of the signed claims. Never accept mutable arguments
	// supplied by the command transport after signature verification.
	out, err := e.runner.Run(ctx, c.Action, cloneArguments(c.Arguments))
	if err != nil {
		return nil, fmt.Errorf("execute remote action: %w", err)
	}
	if len(out) > e.max {
		return nil, fmt.Errorf("remote action output exceeds limit")
	}
	return out, nil
}
func validClaims(c ActionClaims) bool {
	if c.ID == "" || len(c.ID) > 128 || c.TenantID == "" || c.EndpointID == "" || c.ExpiresAt.IsZero() {
		return false
	}
	switch c.Action {
	case ActionKillProcess, ActionCollectFile, ActionReadMemory, ActionListPersistence, ActionQuarantine, ActionReleaseQuarantine:
		if len(c.Arguments) > 16 {
			return false
		}
		for key, value := range c.Arguments {
			if key == "" || len(key) > 64 || len(value) > 4096 {
				return false
			}
		}
		return true
	}
	return false
}

func cloneArguments(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
