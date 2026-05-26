//go:build darwin

package loader

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type Loader struct {
	iface *net.Interface
}

type MapHandles struct {
	Blocklist   *ebpf.Map
	BlocklistV6 *ebpf.Map
	RateMap     *ebpf.Map
	RateMapV6   *ebpf.Map
	StatsMap    *ebpf.Map
	ConfigMap   *ebpf.Map
	Events      *ebpf.Map
}

func New(cfg *model.Config) (*Loader, *MapHandles, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		iface = &net.Interface{Index: 1, Name: cfg.Interface}
	}
	return &Loader{iface: iface}, &MapHandles{}, nil
}

func (l *Loader) Close() error {
	return nil
}
