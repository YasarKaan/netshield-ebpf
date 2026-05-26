import { useEffect, useState } from 'react';
import { useStore } from '../store';

export function Events() {
  const { apiUrl, token, events, setEvents } = useStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [limit] = useState(15);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [filterReason, setFilterReason] = useState('');

  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    let active = true;

    const load = async () => {
      setLoading(true);
      setError('');
      try {
        const url = `${apiUrl}/api/v1/events?limit=${limit}&offset=${offset}&reason=${filterReason}`;
        const resp = await fetch(url, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (!resp.ok) throw new Error(`API returned status ${resp.status}`);
        const data = await resp.json();
        if (active) {
          setEvents(data.events || []);
          setTotal(data.total || 0);
        }
      } catch (err: unknown) {
        if (active) {
          setError('Failed to fetch events: ' + (err instanceof Error ? err.message : String(err)));
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    load();
    const intervalId = setInterval(load, 30000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [apiUrl, token, offset, limit, filterReason, refreshTrigger, setEvents]);

  const handlePrevPage = () => {
    if (offset >= limit) {
      setOffset(offset - limit);
    }
  };

  const handleNextPage = () => {
    if (offset + limit < total) {
      setOffset(offset + limit);
    }
  };

  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="card">
      <div className="chart-header">
        <h3 className="chart-title">Security Mitigation Logs ({total})</h3>
        <div style={{ display: 'flex', gap: '12px' }}>
          <select
            className="form-input"
            style={{ width: '160px', padding: '6px 12px', fontSize: '13px' }}
            value={filterReason}
            onChange={(e) => {
              setFilterReason(e.target.value);
              setOffset(0); // Reset page on filter change
            }}
          >
            <option value="">All Reasons</option>
            <option value="rate_limit">Rate Limit</option>
            <option value="port_scan">Port Scan</option>
            <option value="manual">Manual</option>
          </select>
          <button className="btn btn-primary" style={{ padding: '6px 12px', fontSize: '13px' }} onClick={() => setRefreshTrigger(prev => prev + 1)} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: 'rgba(255, 51, 102, 0.15)', border: '1px solid var(--accent-red)', borderRadius: '6px', color: 'var(--accent-red)', marginBottom: '16px', fontSize: '14px' }}>
          {error}
        </div>
      )}

      <div className="table-container" style={{ marginBottom: '20px' }}>
        <table className="custom-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>IP Address</th>
              <th>Reason</th>
              <th>Details</th>
              <th>Geographic Source</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={`${e.ip}-${e.blocked_at}`}>
                <td style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                  {new Date(e.blocked_at).toLocaleString()}
                </td>
                <td style={{ fontWeight: '600' }}>{e.ip}</td>
                <td>
                  <span className={`badge ${e.reason.replace('_', '-')}`}>{e.reason}</span>
                </td>
                <td style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>{e.detail}</td>
                <td>
                  {e.country ? `${e.country} (Lat: ${e.lat?.toFixed(1)}, Lon: ${e.lon?.toFixed(1)})` : 'US'}
                </td>
              </tr>
            ))}
            {events.length === 0 && !loading && (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                  No security events found.
                </td>
              </tr>
            )}
            {loading && (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-secondary)' }}>
                  Loading events...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          Showing page {currentPage} of {totalPages}
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn-danger" style={{ padding: '8px 16px', fontSize: '12px' }} onClick={handlePrevPage} disabled={offset === 0 || loading}>
            Previous
          </button>
          <button className="btn btn-primary" style={{ padding: '8px 16px', fontSize: '12px' }} onClick={handleNextPage} disabled={offset + limit >= total || loading}>
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
