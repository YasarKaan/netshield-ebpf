import { useStore, type BlockEntry } from '../store';

export function ThreatRadar() {
  const blockedIPs = useStore((s) => s.blockedIPs);

  // Map lat (-90 to 90) and lon (-180 to 180) to radial coordinates inside a 300x300 SVG
  const mapGeoToRadar = (lat: number = 37.751, lon: number = -97.822) => {
    // radius between 30 and 130
    const radius = ((90 - lat) / 180) * 90 + 30;
    const angle = ((lon + 180) / 360) * 2 * Math.PI;
    const x = 150 + radius * Math.cos(angle);
    const y = 150 + radius * Math.sin(angle);
    return { x, y };
  };

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="chart-header">
        <h3 className="chart-title">Threat Mitigation Radar</h3>
        <span className="badge rate-limit pulse" style={{ fontSize: '11px' }}>
          Live Stream
        </span>
      </div>
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flexGrow: 1, position: 'relative', minHeight: '260px' }}>
        <svg width="280" height="280" viewBox="0 0 300 300" style={{ background: '#070a12', borderRadius: '50%', border: '1px solid #1e2638' }}>
          <defs>
            <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(0, 242, 254, 0.15)" />
              <stop offset="100%" stopColor="rgba(7, 10, 18, 0)" />
            </radialGradient>
            <linearGradient id="sweepGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="rgba(0, 242, 254, 0)" />
              <stop offset="100%" stopColor="var(--accent-cyan)" />
            </linearGradient>
          </defs>

          {/* Radar Circles */}
          <circle cx="150" cy="150" r="140" fill="none" stroke="#122538" strokeWidth="1" />
          <circle cx="150" cy="150" r="100" fill="none" stroke="#122538" strokeWidth="1" />
          <circle cx="150" cy="150" r="60" fill="none" stroke="#122538" strokeWidth="1" />
          <circle cx="150" cy="150" r="20" fill="none" stroke="#122538" strokeWidth="1" />

          {/* Radar Crosshairs */}
          <line x1="10" y1="150" x2="290" y2="150" stroke="#122538" strokeWidth="1" />
          <line x1="150" y1="10" x2="150" y2="290" stroke="#122538" strokeWidth="1" />

          {/* Sector Angles */}
          <line x1="51" y1="51" x2="249" y2="249" stroke="#0e1b29" strokeWidth="1" strokeDasharray="3,3" />
          <line x1="51" y1="249" x2="249" y2="51" stroke="#0e1b29" strokeWidth="1" strokeDasharray="3,3" />

          {/* Sweep line */}
          <g className="radar-sweep">
            <line
              x1="150"
              y1="150"
              x2="290"
              y2="150"
              stroke="rgba(0, 242, 254, 0.8)"
              strokeWidth="2"
            />

            {/* Sweep glow */}
            <path
              d="M 150 150 L 276.9 90.8 A 140 140 0 0 1 290 150 Z"
              fill="url(#sweepGrad)"
              opacity="0.25"
            />
          </g>

          {/* Central radar glow */}
          <circle cx="150" cy="150" r="140" fill="url(#radarGlow)" />

          {/* Blocked IP Markers */}
          {blockedIPs.slice(0, 12).map((ip: BlockEntry, idx: number) => {
            const { x, y } = mapGeoToRadar(ip.lat, ip.lon);
            const isRecent = idx === 0; // Highlight the absolute newest block
            return (
              <g key={ip.ip}>
                {isRecent && (
                  <circle cx={x} cy={y} r="8" fill="none" stroke="var(--accent-red)" strokeWidth="1" className="pulse">
                    <animate attributeName="r" values="4;12;4" dur="2s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="1;0;1" dur="2s" repeatCount="indefinite" />
                  </circle>
                )}
                <circle
                  cx={x}
                  cy={y}
                  r={isRecent ? '4' : '3'}
                  fill={isRecent ? 'var(--accent-red)' : 'var(--accent-orange)'}
                  style={{ filter: `drop-shadow(0 0 4px ${isRecent ? 'var(--accent-red)' : 'var(--accent-orange)'})` }}
                >
                  <title>{`${ip.ip} (${ip.reason}) - ${ip.country}`}</title>
                </circle>
              </g>
            );
          })}
        </svg>

        {/* Floating details of the latest blocked IP */}
        {blockedIPs.length > 0 && (
          <div style={{ position: 'absolute', bottom: '10px', left: '10px', right: '10px', background: 'rgba(10, 13, 20, 0.85)', padding: '8px 12px', borderRadius: '6px', fontSize: '11px', border: '1px solid var(--border-color)', color: varColor(blockedIPs[0].reason) }}>
            <strong>NEW BLOCKED ATTACKER:</strong> {blockedIPs[0].ip} ({blockedIPs[0].country}) - {blockedIPs[0].detail}
          </div>
        )}
      </div>
    </div>
  );
}

function varColor(reason: string) {
  if (reason === 'rate_limit') return 'var(--accent-red)';
  if (reason === 'port_scan') return 'var(--accent-orange)';
  return 'var(--accent-cyan)';
}
