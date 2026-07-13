package ransomware

import (
	"context"
	"errors"
	"testing"
)

type fakeSuspender struct {
	calls int
	err   error
}

func (s *fakeSuspender) Suspend(context.Context, int) error { s.calls++; return s.err }

type fakeRecorder struct{ calls int }

func (r *fakeRecorder) Record(context.Context, Detection) error { r.calls++; return nil }

func TestCanaryTouchSuspendsBeforeRecording(t *testing.T) {
	order := []string{}
	s := suspendFunc(func(context.Context, int) error { order = append(order, "suspend"); return nil })
	r := recordFunc(func(context.Context, Detection) error { order = append(order, "record"); return nil })
	shield := NewShield(s, r, Policy{RenameBurst: 10, EntropyThreshold: 7.5})
	if err := shield.Observe(context.Background(), Event{PID: 42, Canary: true}); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "suspend" {
		t.Fatalf("order = %v", order)
	}
}

func TestSuspensionFailureFailsClosedAndDoesNotRecord(t *testing.T) {
	s := &fakeSuspender{err: errors.New("denied")}
	r := &fakeRecorder{}
	err := NewShield(s, r, Policy{RenameBurst: 2, EntropyThreshold: 7}).Observe(context.Background(), Event{PID: 7, RenameCount: 3})
	if err == nil || s.calls != 1 || r.calls != 0 {
		t.Fatal("suspension failure must halt processing")
	}
}

type suspendFunc func(context.Context, int) error

func (f suspendFunc) Suspend(c context.Context, p int) error { return f(c, p) }

type recordFunc func(context.Context, Detection) error

func (f recordFunc) Record(c context.Context, d Detection) error { return f(c, d) }
