package blocker

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

func TestBlockerMockOperations(t *testing.T) {
	ctx := context.Background()
	b := New(ctx, nil, nil, true)
	defer b.Close()

	ip := net.ParseIP("198.51.100.22")

	// Block IP
	err := b.Block(ctx, ip, model.ReasonRateLimit, 50*time.Millisecond, "Simulated block")
	if err != nil {
		t.Fatalf("expected no error during mock Block, got: %v", err)
	}

	// Verify blocked IP count
	if count := b.GetBlockedIPCount(); count != 1 {
		t.Errorf("expected blocked IP count to be 1, got: %d", count)
	}

	// List blocked entries
	entries, err := b.List()
	if err != nil {
		t.Fatalf("expected no error during List, got: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 listed entry, got: %d", len(entries))
	}

	if entries[0].IP.String() != "198.51.100.22" {
		t.Errorf("expected listed entry IP to be 198.51.100.22, got: %s", entries[0].IP.String())
	}

	// Wait for TTL expiration
	time.Sleep(100 * time.Millisecond)

	// Verify blocked IP count expired
	if count := b.GetBlockedIPCount(); count != 0 {
		t.Errorf("expected blocked IP count to expire to 0, got: %d", count)
	}

	// Block again and unblock manually
	_ = b.Block(ctx, ip, model.ReasonPortScan, 1*time.Minute, "Manual test")
	if count := b.GetBlockedIPCount(); count != 1 {
		t.Errorf("expected blocked IP count to be 1, got: %d", count)
	}

	err = b.Unblock(ctx, ip)
	if err != nil {
		t.Fatalf("expected no error during Unblock, got: %v", err)
	}

	if count := b.GetBlockedIPCount(); count != 0 {
		t.Errorf("expected blocked IP count to be 0 after Unblock, got: %d", count)
	}
}

func TestBlockerIsBlockedHelpers(t *testing.T) {
	ctx := context.Background()
	b := New(ctx, nil, nil, true)
	defer b.Close()

	ip := net.ParseIP("198.51.100.77")
	if err := b.Block(ctx, ip, model.ReasonManual, time.Minute, "helper test"); err != nil {
		t.Fatalf("block ip: %v", err)
	}

	if !b.IsBlocked(ip) {
		t.Fatal("expected IsBlocked to return true for active block")
	}
	if !b.IsBlockedStr(ip.String()) {
		t.Fatal("expected IsBlockedStr to return true for active block")
	}
	if b.IsBlocked(nil) {
		t.Fatal("expected nil IP to be treated as not blocked")
	}
	if b.IsBlockedStr("198.51.100.200") {
		t.Fatal("expected unknown IP to not be blocked")
	}
}

func TestIPToKey4(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want uint32
	}{
		{name: "ipv4", ip: net.ParseIP("198.51.100.22").To4(), want: 0xc6336416},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipToKey4(tt.ip); got != tt.want {
				t.Fatalf("ipToKey4(%v) = %d, want %d", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIPToKey6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	key := ipToKey6(ip)
	// First two bytes of 2001:db8::1 are 0x20, 0x01
	if key[0] != 0x20 || key[1] != 0x01 {
		t.Errorf("ipToKey6: unexpected first bytes %02x %02x", key[0], key[1])
	}
	if len(key) != 16 {
		t.Errorf("ipToKey6 key length: got %d, want 16", len(key))
	}
}

func TestCleanupLoopRemovesExpiredEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := New(ctx, nil, nil, true)
	defer b.Close()

	ip := net.ParseIP("198.51.100.88")
	if err := b.Block(ctx, ip, model.ReasonRateLimit, 10*time.Millisecond, "expiring block"); err != nil {
		t.Fatalf("block ip: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.RLock()
		_, exists := b.blockedIPs[ip.String()]
		b.mu.RUnlock()
		if !exists {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("expected cleanupLoop to remove expired block entry from internal map")
}

func TestBlockRejectsDuplicateIP(t *testing.T) {
	ctx := context.Background()
	b := New(ctx, nil, nil, true)
	defer b.Close()

	ip := net.ParseIP("198.51.100.99")
	if err := b.Block(ctx, ip, model.ReasonManual, time.Minute, "first"); err != nil {
		t.Fatalf("initial block failed: %v", err)
	}

	err := b.Block(ctx, ip, model.ReasonManual, time.Minute, "duplicate")
	if !errors.Is(err, ErrAlreadyBlocked) {
		t.Fatalf("expected ErrAlreadyBlocked, got %v", err)
	}
}

func TestUnblockMissingIPReturnsErrNotBlocked(t *testing.T) {
	ctx := context.Background()
	b := New(ctx, nil, nil, true)
	defer b.Close()

	err := b.Unblock(ctx, net.ParseIP("198.51.100.123"))
	if !errors.Is(err, ErrNotBlocked) {
		t.Fatalf("expected ErrNotBlocked, got %v", err)
	}
}
