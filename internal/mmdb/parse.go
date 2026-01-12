package mmdb

import (
	"net"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type Reader struct {
	db *maxminddb.Reader
}

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

func Open(path string) (*Reader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &Reader{db: r}, nil
}

func (r *Reader) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func (r *Reader) CountryCode(ip net.IP) (string, error) {
	if r == nil || r.db == nil || ip == nil {
		return "", nil
	}
	var rec record
	if err := r.db.Lookup(ip, &rec); err != nil {
		return "", err
	}
	code := rec.Country.ISOCode
	if code == "" {
		code = rec.RegisteredCountry.ISOCode
	}
	return strings.ToUpper(code), nil
}
