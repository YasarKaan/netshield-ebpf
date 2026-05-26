import { useEffect, useState, type FormEvent } from 'react';
import { useStore } from '../store';

export function Blocklist() {
  const { blockedIPs, setBlockedIPs, apiUrl, token } = useStore();
  const [ipInput, setIpInput] = useState('');
  const [commentInput, setCommentInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [refreshTrigger, setRefreshTrigger] = useState(0);

  // Fetch blocklist
  useEffect(() => {
    let active = true;

    const load = async () => {
      try {
        const resp = await fetch(`${apiUrl}/api/v1/blocklist`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (!resp.ok) throw new Error(`API returned status ${resp.status}`);
        const data = await resp.json();
        if (active) {
          setBlockedIPs(data.entries || []);
        }
      } catch (err: unknown) {
        if (active) {
          setError('Failed to fetch blocklist: ' + (err instanceof Error ? err.message : String(err)));
        }
      }
    };

    load();
    const intervalId = setInterval(load, 30000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [apiUrl, token, refreshTrigger, setBlockedIPs]);

  // Handle Add Block
  const handleAddBlock = async (e: FormEvent) => {
    e.preventDefault();
    if (!ipInput.trim()) return;

    setLoading(true);
    setError('');
    try {
      const resp = await fetch(`${apiUrl}/api/v1/blocklist`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          ip: ipInput.trim(),
          comment: commentInput.trim() || 'Manual Block',
        }),
      });

      if (!resp.ok) {
        const errData = await resp.json();
        throw new Error(errData.error || `HTTP ${resp.status}`);
      }

      setIpInput('');
      setCommentInput('');
      setRefreshTrigger(prev => prev + 1); // Refresh list
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  // Handle Remove Block
  const handleRemoveBlock = async (ipStr: string) => {
    if (!window.confirm(`Unblock ${ipStr}?`)) {
      return;
    }

    setError('');
    try {
      const resp = await fetch(`${apiUrl}/api/v1/blocklist/${ipStr}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!resp.ok) {
        throw new Error(`Failed to remove IP block: status ${resp.status}`);
      }

      setRefreshTrigger(prev => prev + 1); // Refresh list
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  // Filtered blocklist
  const filteredBlocks = blockedIPs.filter(
    (b) =>
      b.ip.includes(searchQuery) ||
      b.reason.includes(searchQuery) ||
      b.detail.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div>
      <div className="dash-row">
        {/* Table Column */}
        <div className="card">
          <div className="chart-header">
            <h3 className="chart-title">Mitigation Blocklist ({filteredBlocks.length})</h3>
            <input
              type="text"
              placeholder="Search blocked IPs..."
              className="form-input"
              style={{ width: '220px', padding: '8px 12px', fontSize: '13px' }}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {error && (
            <div style={{ padding: '12px 16px', background: 'rgba(255, 51, 102, 0.15)', border: '1px solid var(--accent-red)', borderRadius: '6px', color: 'var(--accent-red)', marginBottom: '16px', fontSize: '14px' }}>
              {error}
            </div>
          )}

          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Reason</th>
                  <th>Details</th>
                  <th>Blocked At</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredBlocks.map((b) => (
                  <tr key={b.ip}>
                    <td style={{ fontWeight: '600' }}>{b.ip}</td>
                    <td>
                      <span className={`badge ${b.reason.replace('_', '-')}`}>{b.reason}</span>
                    </td>
                    <td style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{b.detail}</td>
                    <td style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                      {new Date(b.blocked_at).toLocaleString()}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button className="btn btn-danger" style={{ padding: '6px 12px', fontSize: '12px' }} onClick={() => handleRemoveBlock(b.ip)}>
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredBlocks.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                      No blocked IPs matching search or blocklist is empty.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Form Column */}
        <div className="card" style={{ height: 'fit-content' }}>
          <div className="chart-header">
            <h3 className="chart-title">Add Manual IP Block</h3>
          </div>
          <form onSubmit={handleAddBlock}>
            <div className="form-group">
              <label className="form-label">IPv4 Address</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. 198.51.100.22"
                required
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Block Reason / Comment</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. Malicious probing"
                value={commentInput}
                onChange={(e) => setCommentInput(e.target.value)}
              />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Blocking...' : 'Apply Block'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
