package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/YasarKaan/go-kit/loggerutils"
	"github.com/YasarKaan/netshield-ebpf/internal/exporter"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// packetEventSize must match sizeof(struct packet_event) in bpf/events.h exactly.
//
//	8  (ts_ns)
//	+ 16 (src_addr)
//	+ 16 (dst_addr)
//	+ 2  (src_port)
//	+ 2  (dst_port)
//	+ 2  (pkt_len)
//	+ 1  (protocol)
//	+ 1  (tcp_flags)
//	+ 1  (flags)
//	+ 1  (ip_version)
//	+ 2  (_pad)
//	= 52
const packetEventSize = 52

// PerfReader interface abstracts the ebpf/perf Reader for unit testing.
type PerfReader interface {
	Read() (perf.Record, error)
	Close() error
}

type Collector struct {
	reader PerfReader
	out    chan<- model.PacketEvent
}

func New(eventsMap *ebpf.Map, out chan<- model.PacketEvent) (*Collector, error) {
	if eventsMap == nil {
		// Mock Mode: bypass perf reader initialization
		return &Collector{reader: nil, out: out}, nil
	}
	// Use standard page size for the per-CPU buffers
	rd, err := perf.NewReader(eventsMap, os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("new perf reader: %w", err)
	}
	return &Collector{reader: rd, out: out}, nil
}

func (c *Collector) Run(ctx context.Context) {
	if c.reader == nil {
		loggerutils.InfoContext(ctx, "Collector running in mock mode. Bypassing ring buffer reading.")
		<-ctx.Done()
		return
	}
	defer c.reader.Close()

	loggerutils.InfoContext(ctx, "Starting ring buffer collector...")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			loggerutils.Warn("ring buffer read error", map[string]any{"err": err.Error()})
			continue
		}

		if record.LostSamples > 0 {
			exporter.RingBufferDrops.Add(float64(record.LostSamples))
		}

		if len(record.RawSample) == 0 {
			continue
		}

		ev, err := parseEvent(record.RawSample)
		if err != nil {
			loggerutils.Warn("event parse error", map[string]any{"err": err.Error()})
			continue
		}

		select {
		case c.out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// parseEvent deserializes a raw perf buffer sample into a PacketEvent.
// The layout must match struct packet_event in bpf/events.h exactly.
//
// Byte offsets:
//
//	[0:8]   ts_ns       (uint64 LE)
//	[8:24]  src_addr    (16 bytes; IPv4 uses first 4, rest zero)
//	[24:40] dst_addr    (16 bytes; same)
//	[40:42] src_port    (uint16 LE)
//	[42:44] dst_port    (uint16 LE)
//	[44:46] pkt_len     (uint16 LE)
//	[46]    protocol    (uint8)
//	[47]    tcp_flags   (uint8)
//	[48]    flags       (uint8)
//	[49]    ip_version  (uint8; 4 or 6)
//	[50:52] _pad        (ignored)
func parseEvent(raw []byte) (model.PacketEvent, error) {
	if len(raw) < packetEventSize {
		return model.PacketEvent{}, fmt.Errorf("short event: %d bytes (expected %d)", len(raw), packetEventSize)
	}

	tsNs := binary.LittleEndian.Uint64(raw[0:8])
	srcAddr := raw[8:24]
	dstAddr := raw[24:40]
	srcPort := binary.LittleEndian.Uint16(raw[40:42])
	dstPort := binary.LittleEndian.Uint16(raw[42:44])
	pktLen := binary.LittleEndian.Uint16(raw[44:46])
	proto := raw[46]
	tcpFlags := raw[47]
	// raw[48] = flags (reserved for future use)
	ipVer := raw[49]

	var srcIP, dstIP net.IP
	if ipVer == 6 {
		srcIP = make(net.IP, 16)
		dstIP = make(net.IP, 16)
		copy(srcIP, srcAddr)
		copy(dstIP, dstAddr)
	} else {
		// IPv4: only the first 4 bytes are populated by the XDP program.
		srcIP = make(net.IP, 4)
		dstIP = make(net.IP, 4)
		copy(srcIP, srcAddr[:4])
		copy(dstIP, dstAddr[:4])
	}

	return model.PacketEvent{
		Timestamp: time.Unix(0, int64(tsNs)),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		PktLen:    pktLen,
		Protocol:  proto,
		TCPFlags:  tcpFlags,
	}, nil
}
