package response

import (
	"context"
	"errors"
	"testing"
)

type fakeFirewall struct {
	applied, removed bool
	verifyErr        error
}

func (f *fakeFirewall) Apply(context.Context, ControlEndpoint) error         { f.applied = true; return nil }
func (f *fakeFirewall) VerifyControl(context.Context, ControlEndpoint) error { return f.verifyErr }
func (f *fakeFirewall) Remove(context.Context) error                         { f.removed = true; return nil }

func TestQuarantineKeepsBlockWhenControlVerificationFails(t *testing.T) {
	fw := &fakeFirewall{verifyErr: errors.New("not reachable")}
	m := NewQuarantineManager(fw)
	if err := m.Quarantine(context.Background(), ControlEndpoint{Host: "control.example", Port: 443}); err == nil {
		t.Fatal("expected verification failure")
	}
	if !fw.applied || fw.removed || !m.Active() {
		t.Fatal("block set must remain active after verification failure")
	}
}

func TestQuarantineRejectsInvalidControlEndpoint(t *testing.T) {
	fw := &fakeFirewall{}
	if err := NewQuarantineManager(fw).Quarantine(context.Background(), ControlEndpoint{Host: "", Port: 0}); err == nil {
		t.Fatal("expected invalid endpoint rejection")
	}
	if fw.applied {
		t.Fatal("firewall must not be changed")
	}
}

func TestReleaseRequiresAuthorization(t *testing.T) {
	fw := &fakeFirewall{}
	m := NewQuarantineManager(fw)
	if err := m.Quarantine(context.Background(), ControlEndpoint{Host: "control.example", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if err := m.Release(context.Background(), false); err == nil {
		t.Fatal("expected unauthorized release denial")
	}
	if fw.removed {
		t.Fatal("rules removed without authorization")
	}
}
