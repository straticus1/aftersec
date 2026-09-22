package detection

import (
	"strings"
	"testing"
	"time"
)

func TestActivateHeartbeatActionRejectsUnsignedPrefix(t *testing.T) {
	pub, priv := testKey(t)
	signed, err := SignPack(validPack(), priv)
	if err != nil {
		t.Fatal(err)
	}
	action, err := HeartbeatAction(signed)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(pub)
	rules, err := ActivateHeartbeatAction(action, store, time.Now())
	if err != nil || len(rules) != 1 {
		t.Fatalf("%v %+v", err, rules)
	}
	if _, err := ActivateHeartbeatAction("RUN_SIGMA::dGVzdA==", store, time.Now()); err == nil {
		t.Fatal("accepted unsigned prefix")
	}
	if !strings.HasPrefix(action, HeartbeatPrefix) {
		t.Fatal(action)
	}
}
