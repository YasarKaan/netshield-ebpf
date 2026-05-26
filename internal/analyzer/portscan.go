package analyzer

import (
	"net"
	"sync"
	"time"

	"github.com/YasarKaan/netshield-ebpf/internal/maputils"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type PortScanEntry struct {
	mu    sync.RWMutex
	ports map[uint16]time.Time
}

type PortScanDetector struct {
	cfg     model.PortScanConfig
	entries *maputils.TTLMap[string, *PortScanEntry]
	window  time.Duration
}

func NewPortScanDetector(cfg model.PortScanConfig) *PortScanDetector {
	window, err := time.ParseDuration(cfg.Window)
	if err != nil {
		window = 10 * time.Second
	}

	entries := maputils.NewTTLMap[string, *PortScanEntry](
		maputils.WithTTL[string, *PortScanEntry](5 * time.Minute),
		maputils.WithCleanupInterval[string, *PortScanEntry](30 * time.Second),
	)

	return &PortScanDetector{
		cfg:     cfg,
		entries: entries,
		window:  window,
	}
}

func (ps *PortScanDetector) Record(ip net.IP, port uint16, ts time.Time) bool {
	if port == 0 {
		return false
	}
	key := ip.String()

	entryVal, exists := ps.entries.Get(key)
	if !exists {
		entryVal = &PortScanEntry{
			ports: make(map[uint16]time.Time),
		}
		ps.entries.Set(key, entryVal)
	}

	entryVal.mu.Lock()
	defer entryVal.mu.Unlock()

	entryVal.ports[port] = ts

	cutoff := ts.Add(-ps.window)
	for p, lastHit := range entryVal.ports {
		if lastHit.Before(cutoff) {
			delete(entryVal.ports, p)
		}
	}

	return len(entryVal.ports) >= ps.cfg.DistinctPorts
}

func (ps *PortScanDetector) DistinctPorts(ip net.IP) int {
	key := ip.String()
	entryVal, exists := ps.entries.Get(key)
	if !exists {
		return 0
	}
	entryVal.mu.RLock()
	defer entryVal.mu.RUnlock()
	return len(entryVal.ports)
}

func (ps *PortScanDetector) Close() {
	ps.entries.Close()
}
