package response

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

type ownerLookup map[string]string

func (o ownerLookup) OrganizationForEndpoint(_ context.Context, id string) (string, error) {
	return o[id], nil
}
func TestActionMinterRejectsRoleActionAndCrossTenant(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	m := NewActionMinter(key, ownerLookup{"ep": "org-a"}, time.Minute, time.Now)
	for _, r := range []MintRequest{{Role: "viewer", TenantID: "org-a", EndpointID: "ep", Action: ActionKillProcess}, {Role: "security_operator", TenantID: "org-a", EndpointID: "ep", Action: ActionReadMemory}, {Role: "admin", TenantID: "org-b", EndpointID: "ep", Action: ActionKillProcess}} {
		if _, err := m.Mint(context.Background(), r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
func TestActionMinterDisplayIsOperatorScoped(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	m := NewActionMinter(key, ownerLookup{"ep": "org"}, time.Minute, time.Now)
	if _, err := m.Mint(context.Background(), MintRequest{Role: "viewer", TenantID: "org", EndpointID: "ep", Action: ActionMarkStolen}); err == nil {
		t.Fatal("viewer marked a device stolen")
	}
	if _, err := m.MintDelivered(context.Background(), "org", "ep", ActionKillProcess); err == nil {
		t.Fatal("delivered mint accepted a process kill")
	}
	if _, err := m.Mint(context.Background(), MintRequest{Role: "viewer", TenantID: "org", EndpointID: "ep", Action: ActionDisplayShot}); err == nil {
		t.Fatal("viewer minted a display shot")
	}
	if _, err := m.Mint(context.Background(), MintRequest{Role: "security_operator", TenantID: "org", EndpointID: "ep", Action: ActionDisplayRecord, Arguments: map[string]string{"seconds": "90"}}); err == nil {
		t.Fatal("long recording minted")
	}
	if _, err := m.Mint(context.Background(), MintRequest{Role: "security_operator", TenantID: "org", EndpointID: "ep", Action: ActionDisplayShot, Arguments: map[string]string{"args": "-x"}}); err == nil {
		t.Fatal("display shot accepted arguments")
	}
	if _, err := m.Mint(context.Background(), MintRequest{Role: "admin", TenantID: "org", EndpointID: "ep", Action: ActionDisplayRecord, Arguments: map[string]string{"seconds": "30"}}); err != nil {
		t.Fatal(err)
	}
}

func TestActionMinterBreakGlassIsAdminOnly(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	m := NewActionMinter(key, ownerLookup{"ep": "org"}, time.Minute, time.Now)
	if _, err := m.Mint(context.Background(), MintRequest{Role: "security_operator", TenantID: "org", EndpointID: "ep", Action: ActionBreakGlass, Arguments: map[string]string{"duration": "15m"}}); err == nil {
		t.Fatal("operator minted break-glass")
	}
	if _, err := m.Mint(context.Background(), MintRequest{Role: "admin", TenantID: "org", EndpointID: "ep", Action: ActionBreakGlass, Arguments: map[string]string{"duration": "15m"}}); err != nil {
		t.Fatal(err)
	}
}

func TestActionMinterCreatesEndpointBoundShortLivedToken(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	m := NewActionMinter(key, ownerLookup{"ep": "org"}, time.Minute, func() time.Time { return now })
	token, err := m.Mint(context.Background(), MintRequest{Role: "security_operator", TenantID: "org", EndpointID: "ep", Action: ActionKillProcess})
	if err != nil {
		t.Fatal(err)
	}
	r := &actionRunner{}
	e := NewActionExecutor(pub, "org", "ep", r, 1024, func() time.Time { return now })
	if _, err = e.Execute(context.Background(), token, nil); err != nil {
		t.Fatal(err)
	}
}
