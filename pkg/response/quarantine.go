// Package response implements fail-closed endpoint containment and remote response controls.
package response

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
)

type ControlEndpoint struct {
	Host string
	Port uint16
}
type Firewall interface {
	Apply(context.Context, ControlEndpoint) error
	VerifyControl(context.Context, ControlEndpoint) error
	Remove(context.Context) error
}
type QuarantineManager struct {
	mu       sync.RWMutex
	firewall Firewall
	active   bool
}

func NewQuarantineManager(f Firewall) *QuarantineManager { return &QuarantineManager{firewall: f} }

// Quarantine applies containment before verifying the recovery channel.
// Threats: C2 and lateral movement are blocked; a broken allow rule is reported
// but never causes broad network access to be restored.
func (m *QuarantineManager) Quarantine(ctx context.Context, endpoint ControlEndpoint) error {
	if m.firewall == nil || endpoint.Host == "" || endpoint.Port == 0 || net.ParseIP(endpoint.Host) == nil && !validHostname(endpoint.Host) {
		return fmt.Errorf("valid firewall and control endpoint are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active {
		return nil
	}
	if err := m.firewall.Apply(ctx, endpoint); err != nil {
		return fmt.Errorf("apply containment: %w", err)
	}
	m.active = true
	if err := m.firewall.VerifyControl(ctx, endpoint); err != nil {
		return fmt.Errorf("verify contained control channel %s: %w", net.JoinHostPort(endpoint.Host, strconv.Itoa(int(endpoint.Port))), err)
	}
	return nil
}
func (m *QuarantineManager) Release(ctx context.Context, authorized bool) error {
	if !authorized {
		return fmt.Errorf("quarantine release is not authorized")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	if err := m.firewall.Remove(ctx); err != nil {
		return fmt.Errorf("remove containment: %w", err)
	}
	m.active = false
	return nil
}
func (m *QuarantineManager) Active() bool { m.mu.RLock(); defer m.mu.RUnlock(); return m.active }
func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
