package fim

import (
	"errors"
	"testing"
)

func TestDecideWriteFailsClosedUnlessOutsideRoots(t *testing.T) {
	if DecideWrite(nil, errors.New("evidence"), false) {
		t.Fatal("evidence failure allowed")
	}
	if DecideWrite(ErrMissingWriter, nil, false) {
		t.Fatal("missing writer allowed")
	}
	if DecideWrite(ErrInvalidEvent, nil, false) {
		t.Fatal("invalid event allowed")
	}
	if !DecideWrite(ErrOutsideCriticalPath, nil, false) {
		t.Fatal("ordinary path denied")
	}
	if DecideWrite(ErrOutsideCriticalPath, nil, true) {
		t.Fatal("canary allowed")
	}
	if !DecideWrite(nil, nil, false) {
		t.Fatal("watched path with evidence denied")
	}
}
