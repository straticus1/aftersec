package geoip

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Record is one database row. A zero record means the address was not listed.
type Record struct {
	Country string
	Region  string
	City    string
	ASN     uint
	NetName string
}

// Database looks up one address. A database read error is returned. An
// address that is absent from the file returns a zero record and a nil error.
type Database interface {
	Lookup(netip.Addr) (Record, error)
}

// Names resolves a public address to PTR names. The server uses this only
// when a name was requested. A resolver error leaves the network name empty.
type Names interface {
	LookupAddr(context.Context, string) ([]string, error)
}

// Resolver combines a local database with an optional reverse lookup.
type Resolver struct {
	db    Database
	names Names
	mu    sync.Mutex
	cache map[string]string
	order []string
}

func NewResolver(db Database, names Names) *Resolver {
	return &Resolver{db: db, names: names, cache: map[string]string{}}
}

// Lookup resolves raw. Private, loopback, link-local, multicast, and
// documentation addresses are local and are not queried.
func (r *Resolver) Lookup(ctx context.Context, raw string) (Place, error) {
	if r == nil || r.db == nil {
		return Place{}, fmt.Errorf("geoip database is not configured")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return Place{}, fmt.Errorf("parse geoip address: %w", err)
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return Place{}, fmt.Errorf("geoip address is invalid")
	}
	if !routable(addr) {
		return Place{IP: addr.String(), Local: true}, nil
	}
	rec, err := r.db.Lookup(addr)
	if err != nil {
		return Place{}, err
	}
	place := Place{
		IP: addr.String(), Country: rec.Country, Region: rec.Region, City: rec.City,
		ASN: rec.ASN, NetName: cleanToken(rec.NetName),
		Listed: rec.Country != "" || rec.Region != "" || rec.City != "" || rec.ASN != 0 || rec.NetName != "",
	}
	if r.names != nil {
		place.Ptr = r.ptr(ctx, addr.String())
		if place.NetName == "" {
			place.NetName = place.Ptr
		}
	}
	return place, nil
}

func (r *Resolver) ptr(ctx context.Context, ip string) string {
	r.mu.Lock()
	if name, ok := r.cache[ip]; ok {
		r.mu.Unlock()
		return name
	}
	r.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	names, err := r.names.LookupAddr(ctx, ip)
	name := ""
	if err == nil && len(names) > 0 {
		name = cleanToken(strings.TrimSuffix(names[0], "."))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= 4096 && len(r.order) > 0 {
		delete(r.cache, r.order[0])
		r.order = r.order[1:]
	}
	r.cache[ip] = name
	r.order = append(r.order, ip)
	return name
}

func routable(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || documentation(addr) {
		return false
	}
	return !netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}

func documentation(addr netip.Addr) bool {
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	} {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func cleanToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\r\n\t") {
		return ""
	}
	return value
}
