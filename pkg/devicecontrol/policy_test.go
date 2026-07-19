package devicecontrol

import (
	"errors"
	"testing"
)

func TestPolicyBlocksUnknownDeviceClass(t *testing.T) {
	p := Policy{Mode: BlockUnknown, Allowed: map[DeviceID]Access{"known": ReadWrite}}
	decision, err := p.Decide(Device{ID: "new", Class: "mass-storage", Serial: "s1"})
	if !errors.Is(err, ErrDeviceDenied) || decision != Deny {
		t.Fatalf("decision=%v err=%v", decision, err)
	}
}

func TestPolicyRejectsMissingStableIdentity(t *testing.T) {
	p := Policy{Mode: BlockUnknown}
	if _, err := p.Decide(Device{Class: "mass-storage"}); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("Decide() error=%v", err)
	}
}

func TestReadOnlyPolicyDoesNotAllowWritableMount(t *testing.T) {
	p := Policy{Mode: AllowListed, Allowed: map[DeviceID]Access{"known": ReadOnly}}
	decision, err := p.Decide(Device{ID: "known", Class: "mass-storage", Serial: "s1"})
	if err != nil || decision != ReadOnly {
		t.Fatalf("decision=%v err=%v", decision, err)
	}
}

type fakeMounter struct {
	access Access
	err    error
}

func (m *fakeMounter) Apply(_ Device, access Access) error { m.access = access; return m.err }

func TestControllerFailsClosedWhenMountEnforcementFails(t *testing.T) {
	mounter := &fakeMounter{err: errors.New("authorization unavailable")}
	c := NewController(Policy{Mode: AllowListed, Allowed: map[DeviceID]Access{"known": ReadWrite}}, mounter)
	if err := c.Handle(Device{ID: "known", Class: "mass-storage", Serial: "s1"}); err == nil {
		t.Fatal("expected mount enforcement error")
	}
}
