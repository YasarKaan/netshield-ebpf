import React, { useState } from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import { useStore } from './store';
import { Dashboard } from './pages/Dashboard';
import { Blocklist } from './pages/Blocklist';
import { Events } from './pages/Events';

export default function App() {
  // Bootstrap WebSocket hook
  useWebSocket();

  const { wsConnected, token, setToken } = useStore();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'blocklist' | 'events'>('dashboard');
  const [showConfig, setShowConfig] = useState(false);
  const [tempToken, setTempToken] = useState(token);

  const handleSaveToken = (e: React.FormEvent) => {
    e.preventDefault();
    setToken(tempToken);
    setShowConfig(false);
  };

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <svg className="logo-shield" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span>NETSHIELD</span>
        </div>

        <nav>
          <ul className="nav-list">
            <li>
              <div
                className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
                onClick={() => setActiveTab('dashboard')}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="3" width="7" height="9" />
                  <rect x="14" y="3" width="7" height="5" />
                  <rect x="14" y="12" width="7" height="9" />
                  <rect x="3" y="16" width="7" height="5" />
                </svg>
                Dashboard
              </div>
            </li>
            <li>
              <div
                className={`nav-item ${activeTab === 'blocklist' ? 'active' : ''}`}
                onClick={() => setActiveTab('blocklist')}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                Blocklist
              </div>
            </li>
            <li>
              <div
                className={`nav-item ${activeTab === 'events' ? 'active' : ''}`}
                onClick={() => setActiveTab('events')}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="8" y1="6" x2="21" y2="6" />
                  <line x1="8" y1="12" x2="21" y2="12" />
                  <line x1="8" y1="18" x2="21" y2="18" />
                  <line x1="3" y1="6" x2="3.01" y2="0" />
                  <line x1="3" y1="12" x2="3.01" y2="0" />
                  <line x1="3" y1="18" x2="3.01" y2="0" />
                </svg>
                Event Logs
              </div>
            </li>
          </ul>
        </nav>

        {/* Sidebar Footer Config */}
        <div style={{ marginTop: 'auto', paddingTop: '20px', borderTop: '1px solid var(--border-color)' }}>
          <button className="btn btn-danger" style={{ width: '100%', padding: '10px 16px', fontSize: '13px' }} onClick={() => setShowConfig(!showConfig)}>
            API Config
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="top-bar">
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <h2 style={{ fontSize: '18px', fontWeight: '600' }}>
              {activeTab === 'dashboard' && 'Security Overview'}
              {activeTab === 'blocklist' && 'Blocked Attacker Policies'}
              {activeTab === 'events' && 'Intrusion Logs'}
            </h2>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              NetShield-eBPF Mitigation Control
            </span>
          </div>

          <div className="token-config">
            {/* Connection Status */}
            <div className="status-badge">
              <span className={`status-dot ${wsConnected ? 'connected' : 'disconnected'}`} />
              <span>{wsConnected ? 'Connected to Agent' : 'Agent Offline'}</span>
            </div>
          </div>
        </header>

        <div className="content-body">
          {showConfig && (
            <div className="card" style={{ marginBottom: '24px', border: '1px solid var(--accent-cyan)' }}>
              <div className="chart-header">
                <h3 className="chart-title" style={{ color: 'var(--accent-cyan)' }}>Configure Security Bearer Token</h3>
              </div>
              <form onSubmit={handleSaveToken} style={{ display: 'flex', gap: '16px', alignItems: 'flex-end' }}>
                <div style={{ flexGrow: 1 }}>
                  <label className="form-label">Authorization Token</label>
                  <input
                    type="password"
                    className="form-input"
                    value={tempToken}
                    onChange={(e) => setTempToken(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn btn-primary">
                  Save
                </button>
                <button type="button" className="btn btn-danger" onClick={() => setShowConfig(false)}>
                  Cancel
                </button>
              </form>
            </div>
          )}

          {activeTab === 'dashboard' && <Dashboard />}
          {activeTab === 'blocklist' && <Blocklist />}
          {activeTab === 'events' && <Events />}
        </div>
      </main>
    </div>
  );
}
