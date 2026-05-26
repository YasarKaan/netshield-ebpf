package analyzer

import (
	"net"
	"sync"
	"time"

	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type windowEntry struct {
	mu       sync.Mutex
	buckets  []uint32 // circular bucket array (1s per slot)
	lastSlot int64    // unix second of most recent update
}

type RateLimiter struct {
	cfg     model.RateLimitConfig
	entries sync.Map // net.IP.String() -> *windowEntry
}

func NewRateLimiter(cfg model.RateLimitConfig) *RateLimiter {
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = 1
	}
	return &RateLimiter{
		cfg: cfg,
	}
}

func (rl *RateLimiter) Record(ip net.IP, ts time.Time) (exceeded bool, pps float64) {
	key := ip.String()
	v, _ := rl.entries.LoadOrStore(key, &windowEntry{
		buckets: make([]uint32, rl.cfg.WindowSeconds),
	})
	entry := v.(*windowEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	slot := ts.Unix()
	if slot != entry.lastSlot {
		stale := int(slot - entry.lastSlot)
		if stale >= len(entry.buckets) {
			for i := range entry.buckets {
				entry.buckets[i] = 0
			}
		} else {
			for i := 0; i < stale; i++ {
				entry.buckets[(int(entry.lastSlot)+1+i)%len(entry.buckets)] = 0
			}
		}
		entry.lastSlot = slot
	}

	idx := int(slot) % len(entry.buckets)
	entry.buckets[idx]++

	var total uint32
	for _, b := range entry.buckets {
		total += b
	}

	pps = float64(total) / float64(rl.cfg.WindowSeconds)
	exceeded = pps > float64(rl.cfg.PPS)
	return
}
