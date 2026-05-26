package geoip

import (
	"errors"
	"net"
	"os"

	"github.com/oschwald/geoip2-golang"
)

type LookupClient struct {
	db *geoip2.Reader
}

func New(dbPath string) (*LookupClient, error) {
	if dbPath == "" {
		return &LookupClient{db: nil}, nil
	}
	// Check if file exists
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		// File does not exist, return client with nil db to use fallback
		return &LookupClient{db: nil}, nil
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &LookupClient{db: db}, nil
}

// IsMock returns true if the LookupClient is using the local subnet fallback instead of a real MaxMind DB.
func (c *LookupClient) IsMock() bool {
	return c.db == nil
}


func (c *LookupClient) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

func (c *LookupClient) Lookup(ip net.IP) (string, float64, float64) {
	if ip == nil {
		return "US", 37.751, -97.822
	}

	if c.db != nil {
		record, err := c.db.City(ip)
		if err == nil {
			return record.Country.IsoCode, record.Location.Latitude, record.Location.Longitude
		}
	}

	// Fallback to local subnet map
	return getLocalGeoFallback(ip)
}

func getLocalGeoFallback(ip net.IP) (string, float64, float64) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "US", 37.751, -97.822
	}
	val := int(ip4[3])
	countries := []struct {
		code string
		lat  float64
		lon  float64
	}{
		{"US", 37.751, -97.822},
		{"DE", 51.1657, 10.4515},
		{"CN", 39.9042, 116.4074},
		{"TR", 38.9637, 35.2433},
		{"GB", 55.3781, -3.436},
		{"FR", 46.2276, 2.2137},
		{"JP", 36.2048, 138.2529},
		{"BR", -14.235, -51.9253},
		{"AU", -25.2744, 133.7751},
		{"IN", 20.5937, 78.9629},
	}
	idx := val % len(countries)
	c := countries[idx]
	jitterLat := float64(val%10-5) * 0.5
	jitterLon := float64(val%10-5) * 0.5
	return c.code, c.lat + jitterLat, c.lon + jitterLon
}
