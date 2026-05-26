package blocker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/YasarKaan/go-kit/loggerutils"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
	"github.com/cilium/ebpf"
)

var (
	ErrAlreadyBlocked = errors.New("ip already blocked")
	ErrNotBlocked     = errors.New("ip not blocked")
)

type Blocker struct {
	mu         sync.RWMutex
	m4         *ebpf.Map // IPv4 BPF blocklist (key: uint32)
	m6         *ebpf.Map // IPv6 BPF blocklist (key: [16]byte)
	mockMode   bool
	blockedIPs map[string]time.Time  // ip.String() -> expiry
	blockedAt  map[string]time.Time  // ip.String() -> blocked at
	reasons    map[string]model.BlockReason
	details    map[string]string
	stopChan   chan struct{}
}

// New creates a Blocker backed by two optional BPF maps (IPv4 and IPv6).
// Pass nil for either map in mock mode or when running on non-Linux.
func New(ctx context.Context, m4, m6 *ebpf.Map, mockMode bool) *Blocker {
	b := &Blocker{
		m4:         m4,
		m6:         m6,
		mockMode:   mockMode,
		blockedIPs: make(map[string]time.Time),
		blockedAt:  make(map[string]time.Time),
		reasons:    make(map[string]model.BlockReason),
		details:    make(map[string]string),
		stopChan:   make(chan struct{}),
	}
	go b.cleanupLoop(ctx)
	return b
}

func (b *Blocker) Block(ctx context.Context, ip net.IP, reason model.BlockReason, duration time.Duration, detail string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	ipStr := ip.String()
	if expiry, exists := b.blockedIPs[ipStr]; exists && time.Now().Before(expiry) {
		return ErrAlreadyBlocked
	}

	now := time.Now()
	expiry := now.Add(duration)
	if duration == 0 {
		expiry = now.Add(100 * 365 * 24 * time.Hour)
	}

	b.blockedIPs[ipStr] = expiry
	b.blockedAt[ipStr] = now
	b.reasons[ipStr] = reason
	b.details[ipStr] = detail

	loggerutils.InfoContext(ctx, "Scheduling block for IP: {} (duration: {}, reason: {})", ipStr, duration, reason.String())

	if b.mockMode {
		loggerutils.InfoContext(ctx, "[MOCK-MODE] IP {} inserted to simulated blocklist (expiry: {})", ipStr, expiry.Format(time.RFC3339))
		return nil
	}

	val := uint8(reason)

	if ip4 := ip.To4(); ip4 != nil {
		if b.m4 == nil {
			return nil // no BPF map in this mode
		}
		key := ipToKey4(ip4)
		if err := b.m4.Put(key, val); err != nil {
			return fmt.Errorf("blocklist put %s: %w", ipStr, err)
		}
	} else {
		if b.m6 == nil {
			return nil
		}
		key := ipToKey6(ip)
		if err := b.m6.Put(key, val); err != nil {
			return fmt.Errorf("blocklist_v6 put %s: %w", ipStr, err)
		}
	}

	loggerutils.InfoContext(ctx, "IP {} written to BPF blocklist successfully", ipStr)
	return nil
}

func (b *Blocker) Unblock(ctx context.Context, ip net.IP) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	ipStr := ip.String()
	if _, exists := b.blockedIPs[ipStr]; !exists {
		return ErrNotBlocked
	}

	delete(b.blockedIPs, ipStr)
	delete(b.blockedAt, ipStr)
	delete(b.reasons, ipStr)
	delete(b.details, ipStr)

	loggerutils.InfoContext(ctx, "Removing block for IP: {}", ipStr)

	if b.mockMode {
		loggerutils.InfoContext(ctx, "[MOCK-MODE] IP {} removed from simulated blocklist", ipStr)
		return nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		if b.m4 == nil {
			return nil
		}
		key := ipToKey4(ip4)
		if err := b.m4.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("blocklist delete %s: %w", ipStr, err)
		}
	} else {
		if b.m6 == nil {
			return nil
		}
		key := ipToKey6(ip)
		if err := b.m6.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("blocklist_v6 delete %s: %w", ipStr, err)
		}
	}

	loggerutils.InfoContext(ctx, "IP {} deleted from BPF blocklist successfully", ipStr)
	return nil
}

func (b *Blocker) List() ([]model.BlockEntry, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var entries []model.BlockEntry
	for ipStr, expiry := range b.blockedIPs {
		if time.Now().After(expiry) {
			continue
		}
		ip := net.ParseIP(ipStr)
		entries = append(entries, model.BlockEntry{
			IP:        ip,
			Reason:    b.reasons[ipStr].String(),
			BlockedAt: b.blockedAt[ipStr],
			Detail:    b.details[ipStr],
		})
	}
	return entries, nil
}

func (b *Blocker) GetBlockedIPCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	count := 0
	now := time.Now()
	for _, expiry := range b.blockedIPs {
		if now.Before(expiry) {
			count++
		}
	}
	return count
}

// IsBlocked checks if an IP is currently blocked (considering expiration time).
func (b *Blocker) IsBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return b.IsBlockedStr(ip.String())
}

// IsBlockedStr checks if an IP string is currently blocked (considering expiration time).
func (b *Blocker) IsBlockedStr(ipStr string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	expiry, exists := b.blockedIPs[ipStr]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

func (b *Blocker) Close() {
	close(b.stopChan)
}

func (b *Blocker) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopChan:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var expired []string

			b.mu.Lock()
			for ip, expiry := range b.blockedIPs {
				if now.After(expiry) {
					expired = append(expired, ip)
				}
			}
			b.mu.Unlock()

			for _, ipStr := range expired {
				ip := net.ParseIP(ipStr)
				_ = b.Unblock(ctx, ip)
			}
		}
	}
}

// ipToKey4 converts a 4-byte IPv4 address to the uint32 BPF map key.
func ipToKey4(ip4 net.IP) uint32 {
	return binary.BigEndian.Uint32(ip4)
}

// ipToKey6 converts an IPv6 address to the [16]byte BPF map key.
func ipToKey6(ip net.IP) [16]byte {
	var key [16]byte
	copy(key[:], ip.To16())
	return key
}
