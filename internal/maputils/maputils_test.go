package maputils

import (
	"testing"
	"time"
)

func TestTTLMapBasicOperations(t *testing.T) {
	// Create map with 100ms TTL and 50ms cleanup
	m := NewTTLMap[string, int](
		WithTTL[string, int](100*time.Millisecond),
		WithCleanupInterval[string, int](50*time.Millisecond),
	)
	defer m.Close()

	// 1. Test Get on missing key
	if _, exists := m.Get("missing"); exists {
		t.Error("expected missing key to not exist")
	}

	// 2. Test Set and Get
	m.Set("key1", 42)
	val, exists := m.Get("key1")
	if !exists {
		t.Fatal("expected key1 to exist")
	}
	if val != 42 {
		t.Errorf("expected value 42, got %d", val)
	}

	// 3. Test Delete
	m.Delete("key1")
	if _, exists := m.Get("key1"); exists {
		t.Error("expected key1 to be deleted")
	}
}

func TestTTLMapExpiration(t *testing.T) {
	// Create map with 50ms TTL and 10ms cleanup
	m := NewTTLMap[string, string](
		WithTTL[string, string](50*time.Millisecond),
		WithCleanupInterval[string, string](10*time.Millisecond),
	)
	defer m.Close()

	m.Set("expired_key", "value")

	// Verify it exists immediately
	val, exists := m.Get("expired_key")
	if !exists || val != "value" {
		t.Fatal("expected key to exist initially")
	}

	// Wait for TTL expiration
	time.Sleep(100 * time.Millisecond)

	// Get should return false even before background cleanup deletes it
	if _, exists := m.Get("expired_key"); exists {
		t.Error("expected key to be expired")
	}

	// Lock the map to inspect internal store and verify background cleanup ran
	m.mu.Lock()
	_, existsInStore := m.store["expired_key"]
	m.mu.Unlock()

	if existsInStore {
		t.Error("expected background cleanup to delete expired key from store")
	}
}
