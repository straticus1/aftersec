package geoip

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type mapDB map[netip.Addr]Record

func (m mapDB) Lookup(addr netip.Addr) (Record, error) {
	if addr == netip.MustParseAddr("1.0.0.1") {
		return Record{}, errors.New("database unreadable")
	}
	return m[addr], nil
}

type names struct{ called int }

func (n *names) LookupAddr(context.Context, string) ([]string, error) {
	n.called++
	return []string{"edge.example.net."}, nil
}

func TestLookupLabelsLocalAddressesAndNetworkNames(t *testing.T) {
	db := mapDB{
		netip.MustParseAddr("1.1.1.1"): {Country: "US", Region: "Ohio", City: "Columbus", ASN: 13335, NetName: "CLOUDFLARENET"},
	}
	names := &names{}
	resolver := NewResolver(db, names)
	local, err := resolver.Lookup(context.Background(), "192.168.1.20")
	if err != nil || !local.Local || local.Glance() != "192.168.1.20 local" || names.called != 0 {
		t.Fatalf("%v %+v calls=%d", err, local, names.called)
	}
	carrier, err := resolver.Lookup(context.Background(), "100.64.0.1")
	if err != nil || !carrier.Local || names.called != 0 {
		t.Fatalf("carrier: %v %+v", err, carrier)
	}
	if _, err := resolver.Lookup(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("invalid address accepted")
	}
	for _, raw := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "127.0.0.1", "::1", "fc00::1", "2001:db8::1", "169.254.1.1"} {
		place, err := resolver.Lookup(context.Background(), raw)
		if err != nil || !place.Local || place.Glance() != raw+" local" || names.called != 0 {
			t.Fatalf("%s: %v %+v calls=%d", raw, err, place, names.called)
		}
	}
	public, err := resolver.Lookup(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if public.NetName != "CLOUDFLARENET" || public.Ptr != "edge.example.net" || public.Country != "US" {
		t.Fatalf("%+v", public)
	}
	if public.Glance() != "1.1.1.1 Columbus, Ohio, US net=AS13335 CLOUDFLARENET ptr=edge.example.net" {
		t.Fatalf("%s", public.Glance())
	}
	again, err := resolver.Lookup(context.Background(), "1.1.1.1")
	if err != nil || again.Ptr != public.Ptr || names.called != 1 {
		t.Fatalf("cache: %v %+v calls=%d", err, again, names.called)
	}
	if _, err := resolver.Lookup(context.Background(), "1.0.0.1"); err == nil {
		t.Fatal("database error treated as unlisted")
	}
	missing, err := resolver.Lookup(context.Background(), "8.8.8.8")
	if err != nil || missing.Listed || missing.Glance() != "8.8.8.8 unlisted net=edge.example.net" {
		t.Fatalf("%v %s", err, missing.Glance())
	}
}

func TestOpenRejectsAMissingDatabase(t *testing.T) {
	if _, err := Open("", ""); err == nil {
		t.Fatal("empty paths opened")
	}
	if _, err := Open("/no/such/city.mmdb", ""); err == nil {
		t.Fatal("missing database opened")
	}
}
