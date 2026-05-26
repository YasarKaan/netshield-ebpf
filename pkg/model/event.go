package model

import (
	"net"
	"time"
)

type BlockReason uint8

const (
	ReasonManual    BlockReason = 1
	ReasonRateLimit BlockReason = 2
	ReasonPortScan  BlockReason = 3
)

func (r BlockReason) String() string {
	switch r {
	case ReasonManual:
		return "manual"
	case ReasonRateLimit:
		return "rate_limit"
	case ReasonPortScan:
		return "port_scan"
	default:
		return "unknown"
	}
}

type PacketEvent struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	PktLen    uint16
	Protocol  uint8
	TCPFlags  uint8
}

type BlockDecision struct {
	IP     net.IP
	Reason BlockReason
	Detail string
}

type BlockEntry struct {
	IP        net.IP    `json:"ip"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	Detail    string    `json:"detail"`
	Country   string    `json:"country,omitempty"`
	Lat       float64   `json:"lat,omitempty"`
	Lon       float64   `json:"lon,omitempty"`
}

type WSMessage struct {
	Type           string    `json:"type"`
	Timestamp      time.Time `json:"ts"`
	IP             string    `json:"ip,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Detail         string    `json:"detail,omitempty"`
	Country        string    `json:"country,omitempty"`
	Lat            float64   `json:"lat,omitempty"`
	Lon            float64   `json:"lon,omitempty"`
	TotalPackets   uint64    `json:"total_packets,omitempty"`
	DroppedPackets uint64    `json:"dropped_packets,omitempty"`
	ActiveBlocks   uint32    `json:"active_blocks,omitempty"`
	PPSCurrent     uint64    `json:"pps_current,omitempty"`
}
