package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf/perf"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/YasarKaan/netshield-ebpf/internal/exporter"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

// buildIPv4Event constructs a 52-byte packet_event buffer for an IPv4 packet.
func buildIPv4Event(srcIP, dstIP string, srcPort, dstPort, pktLen uint16, proto, tcpFlags byte) []byte {
	buf := make([]byte, packetEventSize)

	binary.LittleEndian.PutUint64(buf[0:8], uint64(time.Now().UnixNano()))

	copy(buf[8:12], net.ParseIP(srcIP).To4())   // src_addr, first 4 bytes
	copy(buf[24:28], net.ParseIP(dstIP).To4())  // dst_addr, first 4 bytes

	binary.LittleEndian.PutUint16(buf[40:42], srcPort)
	binary.LittleEndian.PutUint16(buf[42:44], dstPort)
	binary.LittleEndian.PutUint16(buf[44:46], pktLen)
	buf[46] = proto
	buf[47] = tcpFlags
	buf[49] = 4 // ip_version = 4
	return buf
}

// buildIPv6Event constructs a 52-byte packet_event buffer for an IPv6 packet.
func buildIPv6Event(srcIP, dstIP string, srcPort, dstPort, pktLen uint16, proto byte) []byte {
	buf := make([]byte, packetEventSize)

	binary.LittleEndian.PutUint64(buf[0:8], uint64(time.Now().UnixNano()))

	copy(buf[8:24], net.ParseIP(srcIP).To16())  // src_addr full 16 bytes
	copy(buf[24:40], net.ParseIP(dstIP).To16()) // dst_addr full 16 bytes

	binary.LittleEndian.PutUint16(buf[40:42], srcPort)
	binary.LittleEndian.PutUint16(buf[42:44], dstPort)
	binary.LittleEndian.PutUint16(buf[44:46], pktLen)
	buf[46] = proto
	buf[49] = 6 // ip_version = 6
	return buf
}

func TestParseEventIPv4(t *testing.T) {
	buf := buildIPv4Event("198.51.100.15", "192.168.1.5", 12345, 80, 64, 6, 2)

	ev, err := parseEvent(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if ev.SrcIP.String() != "198.51.100.15" {
		t.Errorf("SrcIP: got %s, want 198.51.100.15", ev.SrcIP)
	}
	if ev.DstIP.String() != "192.168.1.5" {
		t.Errorf("DstIP: got %s, want 192.168.1.5", ev.DstIP)
	}
	if ev.SrcPort != 12345 {
		t.Errorf("SrcPort: got %d, want 12345", ev.SrcPort)
	}
	if ev.DstPort != 80 {
		t.Errorf("DstPort: got %d, want 80", ev.DstPort)
	}
	if ev.PktLen != 64 {
		t.Errorf("PktLen: got %d, want 64", ev.PktLen)
	}
	if ev.Protocol != 6 {
		t.Errorf("Protocol: got %d, want 6 (TCP)", ev.Protocol)
	}
	if ev.TCPFlags != 2 {
		t.Errorf("TCPFlags: got %d, want 2 (SYN)", ev.TCPFlags)
	}
	if len(ev.SrcIP) != 4 {
		t.Errorf("expected 4-byte IPv4 net.IP, got len %d", len(ev.SrcIP))
	}
}

func TestParseEventIPv6(t *testing.T) {
	buf := buildIPv6Event("2001:db8::1", "2001:db8::2", 443, 54321, 128, 6)

	ev, err := parseEvent(buf)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if ev.SrcIP.String() != "2001:db8::1" {
		t.Errorf("SrcIP: got %s, want 2001:db8::1", ev.SrcIP)
	}
	if ev.DstIP.String() != "2001:db8::2" {
		t.Errorf("DstIP: got %s, want 2001:db8::2", ev.DstIP)
	}
	if ev.SrcPort != 443 {
		t.Errorf("SrcPort: got %d, want 443", ev.SrcPort)
	}
	if ev.DstPort != 54321 {
		t.Errorf("DstPort: got %d, want 54321", ev.DstPort)
	}
	if ev.PktLen != 128 {
		t.Errorf("PktLen: got %d, want 128", ev.PktLen)
	}
	if len(ev.SrcIP) != 16 {
		t.Errorf("expected 16-byte IPv6 net.IP, got len %d", len(ev.SrcIP))
	}
}

func TestParseEventShortBuffer(t *testing.T) {
	_, err := parseEvent(make([]byte, 24)) // old size, must fail now
	if err == nil {
		t.Error("expected error for short buffer, got nil")
	}
}

func TestCollectorMock(t *testing.T) {
	packetChan := make(chan model.PacketEvent, 10)
	c, err := New(nil, packetChan)
	if err != nil {
		t.Fatalf("expected no error in mock collector initialization, got: %v", err)
	}
	if c == nil {
		t.Fatal("expected collector to be non-nil")
	}
	if c.reader != nil {
		t.Fatal("expected reader to be nil in mock mode")
	}
}

type mockPerfReader struct {
	records []perf.Record
	idx     int
}

func (m *mockPerfReader) Read() (perf.Record, error) {
	if m.idx >= len(m.records) {
		time.Sleep(10 * time.Millisecond) // simulate waiting for next event
		return perf.Record{}, fmt.Errorf("no more records")
	}
	rec := m.records[m.idx]
	m.idx++
	return rec, nil
}

func (m *mockPerfReader) Close() error { return nil }

func TestCollectorRunLoop(t *testing.T) {
	buf := buildIPv4Event("198.51.100.15", "192.168.1.5", 12345, 80, 64, 6, 2)

	records := []perf.Record{
		{LostSamples: 5},
		{RawSample: buf},
	}

	mr := &mockPerfReader{records: records}
	out := make(chan model.PacketEvent, 10)
	c := &Collector{reader: mr, out: out}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startDrops := testutil.ToFloat64(exporter.RingBufferDrops)
	go c.Run(ctx)

	select {
	case ev := <-out:
		if ev.SrcIP.String() != "198.51.100.15" {
			t.Errorf("expected SrcIP 198.51.100.15, got %s", ev.SrcIP.String())
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for parsed event")
	}

	endDrops := testutil.ToFloat64(exporter.RingBufferDrops)
	if endDrops-startDrops != 5 {
		t.Errorf("expected RingBufferDrops to increase by 5, got delta %f", endDrops-startDrops)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
}
