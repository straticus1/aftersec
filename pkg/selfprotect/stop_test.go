package selfprotect

import (
	"errors"
	"testing"
)

func TestAuthorizeStopFailsClosedWithoutTrustedSigner(t *testing.T) {
	g := NewGuard([]string{"/usr/local/aftersecd"})
	if err := g.AuthorizeStop(false); !errors.Is(err, ErrUnauthorizedStop) {
		t.Fatalf("untrusted: %v", err)
	}
	if err := g.AuthorizeStop(true); err != nil {
		t.Fatal(err)
	}
	var none *Guard
	if err := none.AuthorizeStop(true); !errors.Is(err, ErrInvalidStopPolicy) {
		t.Fatal(err)
	}
}

func TestEntitlementsRevoked(t *testing.T) {
	if err := EntitlementsRevoked([]string{"com.apple.developer.endpoint-security.client"}, []string{"com.apple.developer.endpoint-security.client"}); err != nil {
		t.Fatal(err)
	}
	if err := EntitlementsRevoked([]string{"es.client"}, []string{"network.client"}); !errors.Is(err, ErrEntitlementRevoked) {
		t.Fatal(err)
	}
	if err := EntitlementsRevoked(nil, nil); !errors.Is(err, ErrInvalidStopPolicy) {
		t.Fatal(err)
	}
}
