//go:build linux

package loader

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" XdpDrop ../../bpf/xdp_drop.c

type Loader struct {
	objs    XdpDropObjects
	xdpLink link.Link
	iface   *net.Interface
}

type MapHandles struct {
	Blocklist   *ebpf.Map // IPv4 blocklist (key: uint32)
	BlocklistV6 *ebpf.Map // IPv6 blocklist (key: [16]byte / struct in6_addr)
	RateMap     *ebpf.Map // IPv4 rate tracking
	RateMapV6   *ebpf.Map // IPv6 rate tracking
	StatsMap    *ebpf.Map
	ConfigMap   *ebpf.Map
	Events      *ebpf.Map
}

func New(cfg *model.Config) (*Loader, *MapHandles, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("remove memlock: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %q: %w", cfg.Interface, err)
	}

	var objs XdpDropObjects
	if err := LoadXdpDropObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	// Write initial config
	initCfg := XdpDropNsConfig{
		CoarsePpsLimit: uint32(cfg.Analyzer.CoarsePPSLimit),
		SampleEveryN:   uint32(cfg.Analyzer.SampleEveryN),
		Enabled:        1,
	}
	key := uint32(0)
	if err := objs.ConfigMap.Put(key, initCfg); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("write config map: %w", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.NetshieldXdp,
		Interface: iface.Index,
		Flags:     attachMode(cfg),
	})
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attach XDP to %s: %w", cfg.Interface, err)
	}

	handles := &MapHandles{
		Blocklist:   objs.BlocklistMap,
		BlocklistV6: objs.BlocklistV6Map,
		RateMap:     objs.RateMap,
		RateMapV6:   objs.RateV6Map,
		StatsMap:    objs.StatsMap,
		ConfigMap:   objs.ConfigMap,
		Events:      objs.Events,
	}

	return &Loader{objs: objs, xdpLink: xdpLink, iface: iface}, handles, nil
}

func (l *Loader) Close() error {
	if err := l.xdpLink.Close(); err != nil {
		return fmt.Errorf("detach XDP: %w", err)
	}
	return l.objs.Close()
}

func attachMode(cfg *model.Config) link.XDPAttachFlags {
	switch cfg.XDP.Mode {
	case "native":
		return link.XDPDriverMode
	case "offload":
		return link.XDPOffloadMode
	default:
		return link.XDPGenericMode
	}
}
