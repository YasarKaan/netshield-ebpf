//go:build linux

package loader

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
)

// XDP action constants — must match linux/bpf.h.
const (
	xdpAborted = uint32(0)
	xdpDrop    = uint32(1)
	xdpPass    = uint32(2)
)

// requirePrivileged skips the test if the process cannot remove the BPF
// memory-lock rlimit, which requires root or CAP_BPF.
func requirePrivileged(t *testing.T) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("skipping BPF test (needs root or CAP_BPF): %v", err)
	}
}

// loadObjs compiles and loads the XDP program into the kernel.
// This is where the BPF verifier runs — if the program is rejected the test
// fails immediately with the verifier's error message.
func loadObjs(t *testing.T) *XdpDropObjects {
	t.Helper()
	var objs XdpDropObjects
	if err := LoadXdpDropObjects(&objs, nil); err != nil {
		t.Fatalf("BPF verifier rejected program: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// enableConfig writes a valid ns_config so the XDP program does not return
// XDP_PASS immediately on the "!cfg || !cfg->enabled" early exit.
func enableConfig(t *testing.T, objs *XdpDropObjects, coarsePPS uint32) {
	t.Helper()
	cfg := XdpDropNsConfig{
		Enabled:        1,
		SampleEveryN:   1, // emit every packet so tests are deterministic
		CoarsePpsLimit: coarsePPS,
	}
	key := uint32(0)
	if err := objs.ConfigMap.Put(key, cfg); err != nil {
		t.Fatalf("write config map: %v", err)
	}
}

// ── Packet builders ───────────────────────────────────────────────────────────

// ethIPv4TCP returns a minimal Ethernet + IPv4 + TCP frame (54 bytes).
func ethIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 54)

	// Ethernet header (14 bytes): EtherType = 0x0800 (IPv4)
	pkt[12] = 0x08
	pkt[13] = 0x00

	// IPv4 header (20 bytes, IHL=5, no options)
	ip := pkt[14:]
	ip[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(ip[2:4], 40) // total length
	ip[8] = 64                               // TTL
	ip[9] = 6                                // protocol: TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// TCP header (20 bytes)
	tcp := pkt[34:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50 // data offset = 5

	return pkt
}

// ethIPv6TCP returns a minimal Ethernet + IPv6 + TCP frame (74 bytes).
func ethIPv6TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 74)

	// Ethernet header (14 bytes): EtherType = 0x86DD (IPv6)
	pkt[12] = 0x86
	pkt[13] = 0xDD

	// IPv6 header (40 bytes)
	ip6 := pkt[14:]
	ip6[0] = 0x60                              // version=6
	binary.BigEndian.PutUint16(ip6[4:6], 20)  // payload length (TCP header)
	ip6[6] = 6                                // next header: TCP
	ip6[7] = 64                               // hop limit
	copy(ip6[8:24], srcIP.To16())
	copy(ip6[24:40], dstIP.To16())

	// TCP header (20 bytes)
	tcp := pkt[54:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50

	return pkt
}

// ethARP returns a minimal ARP frame (42 bytes).
func ethARP() []byte {
	pkt := make([]byte, 42)
	pkt[12] = 0x08
	pkt[13] = 0x06 // EtherType = ARP
	return pkt
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestXDPProgramLoadsAndPassesVerifier is the most important test in the file.
// It loads the compiled BPF objects into the kernel, which runs the verifier.
// A verifier rejection means the XDP program has a safety or bounds issue.
func TestXDPProgramLoadsAndPassesVerifier(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	if objs.NetshieldXdp == nil {
		t.Fatal("XDP program handle is nil after successful load")
	}
}

// TestXDPPassesWhenConfigDisabled verifies that the master kill-switch works:
// when no config entry exists (or enabled=0), every packet is passed through.
func TestXDPPassesWhenConfigDisabled(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	// Deliberately do NOT call enableConfig — cfg lookup returns nil → XDP_PASS.

	pkt := ethIPv4TCP(net.ParseIP("1.2.3.4"), net.ParseIP("10.0.0.1"), 12345, 80)
	ret, _, err := objs.NetshieldXdp.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("expected XDP_PASS when config disabled, got %d", ret)
	}
}

// TestXDPPassesNonIPTraffic verifies that ARP (and other non-IP) frames are
// never inspected or dropped.
func TestXDPPassesNonIPTraffic(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	enableConfig(t, objs, 0)

	ret, _, err := objs.NetshieldXdp.Test(ethARP())
	if err != nil {
		t.Fatalf("prog.Test: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("expected XDP_PASS for ARP, got %d", ret)
	}
}

// TestXDPPassesCleanIPv4 verifies that an IPv4 source not on the blocklist
// is passed through.
func TestXDPPassesCleanIPv4(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	enableConfig(t, objs, 0)

	pkt := ethIPv4TCP(net.ParseIP("198.51.100.5"), net.ParseIP("10.0.0.1"), 54321, 443)
	ret, _, err := objs.NetshieldXdp.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("expected XDP_PASS for clean IPv4, got %d", ret)
	}
}

// TestXDPDropsBlockedIPv4 verifies the core blocklist functionality:
// an IPv4 address inserted into blocklist_map must be dropped at the XDP layer.
func TestXDPDropsBlockedIPv4(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	enableConfig(t, objs, 0)

	srcIP := net.ParseIP("198.51.100.99")
	key := binary.BigEndian.Uint32(srcIP.To4())
	val := uint8(1) // reason: manual
	if err := objs.BlocklistMap.Put(key, val); err != nil {
		t.Fatalf("insert into blocklist_map: %v", err)
	}

	pkt := ethIPv4TCP(srcIP, net.ParseIP("10.0.0.1"), 12345, 80)
	ret, _, err := objs.NetshieldXdp.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("expected XDP_DROP for blocked IPv4, got %d", ret)
	}
}

// TestXDPPassesCleanIPv6 verifies that an IPv6 source not on the blocklist
// is passed through.
func TestXDPPassesCleanIPv6(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	enableConfig(t, objs, 0)

	pkt := ethIPv6TCP(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 12345, 443)
	ret, _, err := objs.NetshieldXdp.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test: %v", err)
	}
	if ret != xdpPass {
		t.Errorf("expected XDP_PASS for clean IPv6, got %d", ret)
	}
}

// TestXDPDropsBlockedIPv6 verifies the IPv6 blocklist path.
// This exercises the blocklist_v6_map and the full IPv6 parse block in xdp_drop.c.
func TestXDPDropsBlockedIPv6(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	enableConfig(t, objs, 0)

	srcIP := net.ParseIP("2001:db8::cafe")
	var key [16]byte
	copy(key[:], srcIP.To16())
	val := uint8(1)
	if err := objs.BlocklistV6Map.Put(key, val); err != nil {
		t.Fatalf("insert into blocklist_v6_map: %v", err)
	}

	pkt := ethIPv6TCP(srcIP, net.ParseIP("2001:db8::1"), 12345, 80)
	ret, _, err := objs.NetshieldXdp.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test: %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("expected XDP_DROP for blocked IPv6, got %d", ret)
	}
}

// TestXDPUnblockedAfterRemoval verifies that removing an IP from the blocklist
// causes subsequent packets to be passed again.
func TestXDPUnblockedAfterRemoval(t *testing.T) {
	requirePrivileged(t)
	objs := loadObjs(t)
	enableConfig(t, objs, 0)

	srcIP := net.ParseIP("198.51.100.77")
	key := binary.BigEndian.Uint32(srcIP.To4())
	val := uint8(1)

	// Block
	if err := objs.BlocklistMap.Put(key, val); err != nil {
		t.Fatalf("insert blocklist: %v", err)
	}
	pkt := ethIPv4TCP(srcIP, net.ParseIP("10.0.0.1"), 12345, 80)
	ret, _, err := objs.NetshieldXdp.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test (blocked): %v", err)
	}
	if ret != xdpDrop {
		t.Errorf("expected XDP_DROP while blocked, got %d", ret)
	}

	// Unblock
	if err := objs.BlocklistMap.Delete(key); err != nil {
		t.Fatalf("delete from blocklist: %v", err)
	}
	ret, _, err = objs.NetshieldXdp.Test(pkt)
	if err != nil {
		t.Fatalf("prog.Test (unblocked): %v", err)
	}
	if ret != xdpPass {
		t.Errorf("expected XDP_PASS after unblock, got %d", ret)
	}
}
