package geoip

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/oschwald/maxminddb-golang"
)

// Open reads MaxMind city and ASN databases. Either path may be empty. A
// configured path that cannot be opened is an error.
func Open(cityPath, asnPath string) (*Resolver, error) {
	if cityPath == "" && asnPath == "" {
		return nil, fmt.Errorf("geoip database path is required")
	}
	db := &mmdb{}
	if cityPath != "" {
		reader, err := maxminddb.Open(cityPath)
		if err != nil {
			return nil, fmt.Errorf("open geoip city database: %w", err)
		}
		db.city = reader
	}
	if asnPath != "" {
		reader, err := maxminddb.Open(asnPath)
		if err != nil {
			if db.city != nil {
				db.city.Close()
			}
			return nil, fmt.Errorf("open geoip asn database: %w", err)
		}
		db.asn = reader
	}
	return NewResolver(db, nil), nil
}

func (r *Resolver) Close() error {
	db, ok := r.db.(*mmdb)
	if !ok || db == nil {
		return nil
	}
	var err error
	if db.city != nil {
		err = db.city.Close()
	}
	if db.asn != nil {
		if asnErr := db.asn.Close(); err == nil {
			err = asnErr
		}
	}
	return err
}

// EnablePTR turns on bounded reverse lookups. The network name stays the ASN
// organization when the database has one.
func (r *Resolver) EnablePTR() {
	if r != nil && r.names == nil {
		r.names = &net.Resolver{}
	}
}

type mmdb struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

type cityRow struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

type asnRow struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

func (d *mmdb) Lookup(addr netip.Addr) (Record, error) {
	ip := net.IP(addr.AsSlice())
	var rec Record
	if d.city != nil {
		var row cityRow
		if err := d.city.Lookup(ip, &row); err != nil {
			return Record{}, fmt.Errorf("geoip city lookup: %w", err)
		}
		rec.Country = row.Country.ISOCode
		rec.City = row.City.Names["en"]
		if len(row.Subdivisions) > 0 {
			rec.Region = row.Subdivisions[0].Names["en"]
		}
	}
	if d.asn != nil {
		var row asnRow
		if err := d.asn.Lookup(ip, &row); err != nil {
			return Record{}, fmt.Errorf("geoip asn lookup: %w", err)
		}
		rec.ASN = row.Number
		rec.NetName = row.Org
	}
	return rec, nil
}
