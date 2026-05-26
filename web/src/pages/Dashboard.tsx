import { useStore } from '../store';
import { ThreatRadar } from '../components/ThreatRadar';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';

export function Dashboard() {
  const { totalPackets, droppedPackets, activeBlocks, ppsCurrent, ppsHistory, events } = useStore();

  const formatNumber = (num: number) => {
    if (num >= 1_000_000) return (num / 1_000_000).toFixed(1) + 'M';
    if (num >= 1_000) return (num / 1_000).toFixed(1) + 'K';
    return num.toString();
  };

  return (
    <div>
      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="card">
          <div className="card-title">Current PPS Rate</div>
          <div className="card-value" style={{ color: 'var(--accent-cyan)' }}>{formatNumber(ppsCurrent)}</div>
          <div className="card-desc">Packets per second</div>
        </div>
        <div className="card">
          <div className="card-title">Total Packets</div>
          <div className="card-value">{formatNumber(totalPackets)}</div>
          <div className="card-desc">Processed by XDP hook</div>
        </div>
        <div className="card danger">
          <div className="card-title">Packets Dropped</div>
          <div className="card-value" style={{ color: 'var(--accent-red)' }}>{formatNumber(droppedPackets)}</div>
          <div className="card-desc">Blocked malicious packets</div>
        </div>
        <div className="card">
          <div className="card-title">Active Blocked IPs</div>
          <div className="card-value" style={{ color: 'var(--accent-orange)' }}>{activeBlocks}</div>
          <div className="card-desc">Currently in kernel map</div>
        </div>
      </div>

      {/* Charts & Radar */}
      <div className="dash-row">
        <div className="card chart-card">
          <div className="chart-header">
            <h3 className="chart-title">Real-Time Traffic Rate</h3>
            <span className="badge manual">60s Window</span>
          </div>
          <div style={{ width: '100%', height: '240px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={ppsHistory}>
                <defs>
                  <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-cyan)" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="var(--accent-cyan)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="ts"
                  tickFormatter={(tick) => new Date(tick).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  stroke="var(--text-muted)"
                  fontSize={11}
                  tickLine={false}
                />
                <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  labelFormatter={(label) => new Date(label).toLocaleString()}
                  formatter={(value) => [
                    typeof value === 'number' || typeof value === 'string'
                      ? Number(value).toLocaleString() + ' pps'
                      : '0 pps',
                    'Rate',
                  ]}
                  contentStyle={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                />
                <Area
                  type="monotone"
                  dataKey="pps"
                  stroke="var(--accent-cyan)"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#ppsGrad)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div>
          <ThreatRadar />
        </div>
      </div>

      {/* Recent Blocks Table */}
      <div className="card" style={{ marginBottom: '28px' }}>
        <div className="chart-header">
          <h3 className="chart-title">Recent Block Events</h3>
        </div>
        <div className="table-container">
          <table className="custom-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Reason</th>
                <th>Details</th>
                <th>Country</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 5).map((e) => (
                <tr key={`${e.ip}-${e.blocked_at}`}>
                  <td style={{ fontWeight: '600' }}>{e.ip}</td>
                  <td>
                    <span className={`badge ${e.reason.replace('_', '-')}`}>{e.reason}</span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>{e.detail}</td>
                  <td>{e.country || 'US'}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                    {new Date(e.blocked_at).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                    No attacks detected yet. Waiting for traffic...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
