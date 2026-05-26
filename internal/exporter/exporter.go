package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	PacketsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "netshield_packets_total",
			Help: "Total packets processed by XDP hook.",
		},
		[]string{"action"}, // "passed", "dropped"
	)

	BlockedIPsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "netshield_blocked_ips_total",
		Help: "Current number of IPs in the kernel blocklist.",
	})

	BlockEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "netshield_block_events_total",
			Help: "Total block decisions made by the analyzer.",
		},
		[]string{"reason"}, // "rate_limit", "port_scan", "manual"
	)

	PacketsPerSecond = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "netshield_packets_per_second",
		Help: "Current packet rate observed by the XDP hook.",
	})

	RingBufferDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "netshield_ringbuffer_drops_total",
		Help: "Events dropped due to ring buffer full condition.",
	})

	WebhookErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "netshield_webhook_errors_total",
			Help: "Webhook delivery errors by destination.",
		},
		[]string{"destination"}, // "slack", "discord"
	)

	APIRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "netshield_api_request_duration_seconds",
			Help:    "API request latency.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)
)
