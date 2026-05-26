package analyzer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/YasarKaan/go-kit/loggerutils"
	"github.com/YasarKaan/go-kit/validationutils"
	"github.com/YasarKaan/netshield-ebpf/internal/maputils"
	"github.com/YasarKaan/netshield-ebpf/pkg/model"
)

type Analyzer struct {
	cfg             model.AnalyzerConfig
	rl              *RateLimiter
	ps              *PortScanDetector
	in              <-chan model.PacketEvent
	out             chan<- model.BlockDecision
	mu              sync.RWMutex
	recentlyDecided *maputils.TTLMap[string, bool]
}

func New(cfg model.AnalyzerConfig, in <-chan model.PacketEvent, out chan<- model.BlockDecision) *Analyzer {
	recentlyDecided := maputils.NewTTLMap[string, bool](
		maputils.WithTTL[string, bool](30*time.Second),
		maputils.WithCleanupInterval[string, bool](5*time.Second),
	)
	return &Analyzer{
		cfg:             cfg,
		rl:              NewRateLimiter(cfg.RateLimit),
		ps:              NewPortScanDetector(cfg.PortScan),
		in:              in,
		out:             out,
		recentlyDecided: recentlyDecided,
	}
}

func (a *Analyzer) Run(ctx context.Context) {
	loggerutils.InfoContext(ctx, "Starting packet analyzer...")
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.in:
			if !ok {
				return
			}
			a.evaluate(ctx, ev)
		}
	}
}

func (a *Analyzer) evaluate(ctx context.Context, ev model.PacketEvent) {
	ipStr := ev.SrcIP.String()
	if validationutils.IsPrivateIP(ipStr) || validationutils.IsLoopbackIP(ipStr) || validationutils.IsLinkLocalIP(ipStr) {
		return
	}

	// Check if already recently decided to prevent duplicate emissions
	if _, decided := a.recentlyDecided.Get(ipStr); decided {
		return
	}

	exceeded, pps := a.rl.Record(ev.SrcIP, ev.Timestamp)
	if exceeded {
		a.recentlyDecided.Set(ipStr, true)
		a.emit(ctx, model.BlockDecision{
			IP:     ev.SrcIP,
			Reason: model.ReasonRateLimit,
			Detail: fmt.Sprintf("%.0f pps > threshold %d", pps, a.cfg.RateLimit.PPS),
		})
		loggerutils.WarnContext(ctx, "rate limit exceeded", map[string]any{
			"ip":        ipStr,
			"pps":       pps,
			"threshold": a.cfg.RateLimit.PPS,
		})
		return
	}

	if a.ps.Record(ev.SrcIP, ev.DstPort, ev.Timestamp) {
		distinct := a.ps.DistinctPorts(ev.SrcIP)
		a.recentlyDecided.Set(ipStr, true)
		a.emit(ctx, model.BlockDecision{
			IP:     ev.SrcIP,
			Reason: model.ReasonPortScan,
			Detail: fmt.Sprintf("%d distinct ports in %s", distinct, a.cfg.PortScan.Window),
		})
		loggerutils.WarnContext(ctx, "port scan detected", map[string]any{
			"ip":        ipStr,
			"ports":     distinct,
			"threshold": a.cfg.PortScan.DistinctPorts,
		})
		return
	}
}

func (a *Analyzer) emit(ctx context.Context, d model.BlockDecision) {
	select {
	case a.out <- d:
	default:
		loggerutils.WarnContext(ctx, "block decision channel full, dropping decision", map[string]any{
			"ip": d.IP.String(),
		})
	}
}

func (a *Analyzer) Close() {
	if a.ps != nil {
		a.ps.Close()
	}
	if a.recentlyDecided != nil {
		a.recentlyDecided.Close()
	}
}
