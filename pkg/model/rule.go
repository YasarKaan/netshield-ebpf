package model

type ThreatClassification string

const (
	ThreatClassDDoS     ThreatClassification = "DDoS Attack"
	ThreatClassPortScan ThreatClassification = "Port Scan"
	ThreatClassManual   ThreatClassification = "Manual Exclusion"
)

// ThreatClassification maps BlockReason to its corresponding ThreatClassification constant
func (r BlockReason) ThreatClassification() ThreatClassification {
	switch r {
	case ReasonManual:
		return ThreatClassManual
	case ReasonRateLimit:
		return ThreatClassDDoS
	case ReasonPortScan:
		return ThreatClassPortScan
	default:
		return ThreatClassification("Unknown Threat")
	}
}

