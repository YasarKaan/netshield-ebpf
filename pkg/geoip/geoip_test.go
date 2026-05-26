package geoip

import (
	"net"
	"os"
	"testing"
)

func TestGeoIPMockFallback(t *testing.T) {
	// Test empty path
	client, err := New("")
	if err != nil {
		t.Fatalf("expected no error for empty path, got %v", err)
	}
	if !client.IsMock() {
		t.Error("expected client to be in mock mode when path is empty")
	}

	// Test non-existent path
	client2, err := New("/nonexistent/path/db.mmdb")
	if err != nil {
		t.Fatalf("expected no error for nonexistent path, got %v", err)
	}
	if !client2.IsMock() {
		t.Error("expected client to be in mock mode when path is nonexistent")
	}

	// Test Lookup coordinates and country codes
	country, lat, lon := client.Lookup(net.ParseIP("198.51.100.15"))
	if country == "" {
		t.Error("expected non-empty country code")
	}
	if lat == 0.0 || lon == 0.0 {
		t.Errorf("expected non-zero coordinates, got lat: %f, lon: %f", lat, lon)
	}

	// Test nil IP lookup returns default
	countryNil, latNil, lonNil := client.Lookup(nil)
	if countryNil != "US" {
		t.Errorf("expected default country 'US', got %q", countryNil)
	}
	if latNil != 37.751 || lonNil != -97.822 {
		t.Errorf("expected default coordinates, got lat: %f, lon: %f", latNil, lonNil)
	}

	// Clean up
	err = client.Close()
	if err != nil {
		t.Errorf("failed to close client: %v", err)
	}
}

func TestGeoIPNew_CorruptFile(t *testing.T) {
	// geoip2.Open must return an error for a file with invalid content.
	tmp, err := os.CreateTemp(t.TempDir(), "bad-*.mmdb")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	_, _ = tmp.WriteString("this is not a valid MaxMind database")
	tmp.Close()

	_, err = New(tmp.Name())
	if err == nil {
		t.Error("expected error when opening a corrupt DB file, got nil")
	}
}

func TestGeoIPLookup_IPv6FallbackToUSDefault(t *testing.T) {
	client, _ := New("") // mock mode
	// IPv6 addresses hit the ip.To4() == nil branch inside getLocalGeoFallback.
	ip := net.ParseIP("2001:db8::1")
	country, _, _ := client.Lookup(ip)
	if country != "US" {
		t.Errorf("expected US fallback for IPv6 address, got %q", country)
	}
}
