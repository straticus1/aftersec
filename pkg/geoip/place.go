// Package geoip resolves an IP address to a place and a network name.
//
// Threats: a missing database, a read error, or an unparseable address is
// returned to the caller. Private and non-routable addresses are marked local
// and are not sent to DNS. An address the database does not list is unlisted,
// not a guessed country.
package geoip

import (
	"fmt"
	"strings"
)

// Place is the one-line view of an address.
type Place struct {
	IP      string
	Local   bool
	Country string
	Region  string
	City    string
	ASN     uint
	NetName string
	Ptr     string
	Listed  bool
}

// Glance is a single log field. It does not include a location the lookup
// did not return.
func (p Place) Glance() string {
	if p.Local {
		return p.IP + " local"
	}
	where := strings.Trim(strings.Join([]string{p.City, p.Region, p.Country}, ", "), ", ")
	if where == "" {
		where = "unlisted"
	}
	line := p.IP + " " + where
	if p.ASN != 0 || p.NetName != "" {
		net := p.NetName
		if p.ASN != 0 {
			net = fmt.Sprintf("AS%d %s", p.ASN, p.NetName)
		}
		line += " net=" + strings.TrimSpace(net)
	}
	if p.Ptr != "" && p.Ptr != p.NetName {
		line += " ptr=" + p.Ptr
	}
	return line
}
