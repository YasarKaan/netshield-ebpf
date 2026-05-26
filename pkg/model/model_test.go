package model

import "testing"

func TestBlockReasonString(t *testing.T) {
	tests := []struct {
		reason BlockReason
		want   string
	}{
		{reason: ReasonManual, want: "manual"},
		{reason: ReasonRateLimit, want: "rate_limit"},
		{reason: ReasonPortScan, want: "port_scan"},
		{reason: BlockReason(99), want: "unknown"},
	}

	for _, tt := range tests {
		if got := tt.reason.String(); got != tt.want {
			t.Fatalf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestThreatClassification(t *testing.T) {
	tests := []struct {
		reason BlockReason
		want   ThreatClassification
	}{
		{reason: ReasonManual, want: ThreatClassManual},
		{reason: ReasonRateLimit, want: ThreatClassDDoS},
		{reason: ReasonPortScan, want: ThreatClassPortScan},
		{reason: BlockReason(99), want: ThreatClassification("Unknown Threat")},
	}

	for _, tt := range tests {
		if got := tt.reason.ThreatClassification(); got != tt.want {
			t.Fatalf("ThreatClassification() = %q, want %q", got, tt.want)
		}
	}
}
