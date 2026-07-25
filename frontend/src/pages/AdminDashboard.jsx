import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import '../index.css';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api/v1';

function AdminDashboard() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats]   = useState({ total: 0, critical: 0, high: 0 });
  const [authError, setAuthError] = useState(false);

  const username = localStorage.getItem('ids_username') || 'Admin';

  // Helper — build auth header from stored JWT
  const authHeader = () => ({
    'Authorization': `Bearer ${localStorage.getItem('ids_token')}`,
    'Content-Type':  'application/json',
  });

  // Logout — clear token and redirect
  const handleLogout = async () => {
    try {
      await fetch(`${API}/auth/logout`, {
        method:  'POST',
        headers: authHeader(),
      });
    } catch (_) { /* ignore network errors on logout */ }
    localStorage.removeItem('ids_token');
    localStorage.removeItem('ids_username');
    localStorage.removeItem('ids_role');
    navigate('/login');
  };

  // Fetch alerts (protected — sends JWT)
  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API}/alerts`, { headers: authHeader() });
      if (res.status === 401) {
        setAuthError(true);
        localStorage.removeItem('ids_token');
        navigate('/login');
        return;
      }
      const data = await res.json();
      setAlerts(data);
      let critical = 0, high = 0;
      data.forEach(a => {
        if (a.severity === 'Critical') critical++;
        if (a.severity === 'High')     high++;
      });
      setStats({ total: data.length, critical, high });
    } catch (err) {
      console.error('Failed to fetch alerts', err);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 3000);
    return () => clearInterval(interval);
  }, []);

  const chartData = alerts.map((a, i) => ({
    name: `#${alerts.length - i}`,
    confidence: Math.round(a.confidence * 100),
  })).reverse();

  return (
    <div style={S.page}>
      {/* ── Top Bar ── */}
      <div style={S.topBar}>
        <div>
          <h1 style={S.pageTitle}>Enterprise IDS Dashboard</h1>
          <p style={S.pageSub}>CNN-LSTM Real-Time AI Security Monitoring</p>
        </div>
        <div style={S.topBarRight}>
          <div style={S.userPill}>
            <span style={S.userDot} />
            <span style={{ fontSize: '13px', color: '#10a37f', fontWeight: '600' }}>
              {username}
            </span>
            <span style={{ fontSize: '12px', color: '#555' }}>· Admin</span>
          </div>
          <Link to="/">
            <button style={{ ...S.btn, background: '#1e1e1e', border: '1px solid #333' }}>
              ← Chat
            </button>
          </Link>
          <button onClick={handleLogout} style={{ ...S.btn, background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
            🔓 Logout
          </button>
        </div>
      </div>

      {/* ── Auth error banner ── */}
      {authError && (
        <div style={S.authBanner}>
          ⚠️ Session expired — redirecting to login…
        </div>
      )}

      {/* ── Stat cards ── */}
      <div style={S.cardRow}>
        <StatCard label="Total Intercepted" value={stats.total}    color="#10a37f" icon="🛡️" />
        <StatCard label="Critical Severity"  value={stats.critical} color="#ef4444" icon="🔴" />
        <StatCard label="High Severity"      value={stats.high}     color="#f59e0b" icon="🟡" />
        <StatCard
          label="IDS Status"
          value="ACTIVE"
          color="#10a37f"
          icon="✅"
          small
        />
      </div>

      {/* ── Chart ── */}
      <div style={S.panel}>
        <h3 style={S.panelTitle}>Attack Confidence Timeline</h3>
        <div style={{ height: '260px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f1f1f" />
              <XAxis dataKey="name" stroke="#555" tick={{ fontSize: 11 }} />
              <YAxis stroke="#555" domain={[0, 100]} tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333', borderRadius: '8px' }}
                formatter={(v) => [`${v}%`, 'Confidence']}
              />
              <Line
                type="monotone" dataKey="confidence" stroke="#ef4444"
                strokeWidth={2} dot={{ r: 3, fill: '#ef4444' }}
                activeDot={{ r: 5 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Incident table ── */}
      <div style={S.panel}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ ...S.panelTitle, marginBottom: 0 }}>Incident Logs</h3>
          <span style={{ fontSize: '12px', color: '#555' }}>
            Auto-refresh every 3s · {alerts.length} records
          </span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={S.table}>
            <thead>
              <tr>
                {['Timestamp','Session ID','Attack Type','Severity','Confidence','Payload'].map(h => (
                  <th key={h} style={S.th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => (
                <tr key={alert.id} style={S.tr}>
                  <td style={S.td}>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                  <td style={{ ...S.td, fontFamily: 'monospace', color: '#9b9b9b' }}>
                    {alert.session_id?.substring(0, 8)}…
                  </td>
                  <td style={{ ...S.td, color: '#ef4444' }}>{alert.attack_type}</td>
                  <td style={S.td}>
                    <span style={{
                      padding: '3px 10px', borderRadius: '999px', fontSize: '11px', fontWeight: '600',
                      background: alert.severity === 'Critical' ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)',
                      color:      alert.severity === 'Critical' ? '#ef4444' : '#f59e0b',
                    }}>
                      {alert.severity}
                    </span>
                  </td>
                  <td style={{ ...S.td, color: '#10a37f', fontWeight: '600' }}>
                    {Math.round(alert.confidence * 100)}%
                  </td>
                  <td style={{ ...S.td, fontFamily: 'monospace', color: '#9b9b9b', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {alert.prompt_snippet}
                  </td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan="6" style={{ ...S.td, textAlign: 'center', color: '#444', padding: '40px' }}>
                    No incidents recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p style={S.footerNote}>
        🔐 Authenticated as <strong>{username}</strong> · Session secured with JWT · All actions are logged
      </p>
    </div>
  );
}

function StatCard({ label, value, color, icon, small }) {
  return (
    <div style={S.statCard}>
      <div style={{ fontSize: '20px', marginBottom: '8px' }}>{icon}</div>
      <p style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>{label}</p>
      <p style={{ fontSize: small ? '20px' : '36px', fontWeight: '700', color, margin: 0 }}>{value}</p>
    </div>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────────
const S = {
  page:      { backgroundColor: '#0d0d0d', minHeight: '100vh', color: '#ececec', padding: '32px 40px', fontFamily: "'Inter', sans-serif" },
  topBar:    { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' },
  pageTitle: { fontSize: '26px', fontWeight: '700', margin: '0 0 4px', letterSpacing: '-0.5px' },
  pageSub:   { color: '#555', fontSize: '13px', margin: 0 },
  topBarRight: { display: 'flex', alignItems: 'center', gap: '12px' },
  userPill:  { display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(16,163,127,0.08)', border: '1px solid rgba(16,163,127,0.2)', borderRadius: '999px', padding: '6px 14px' },
  userDot:   { width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#10a37f', boxShadow: '0 0 6px #10a37f' },
  btn:       { padding: '8px 16px', borderRadius: '8px', fontSize: '13px', fontWeight: '500', cursor: 'pointer', color: '#ececec', transition: 'opacity 0.2s' },
  authBanner:{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '8px', padding: '10px 16px', marginBottom: '20px', color: '#ef4444', fontSize: '13px' },
  cardRow:   { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '20px', marginBottom: '28px' },
  statCard:  { backgroundColor: '#141414', padding: '24px', borderRadius: '14px', border: '1px solid #1f1f1f' },
  panel:     { backgroundColor: '#141414', padding: '28px', borderRadius: '14px', border: '1px solid #1f1f1f', marginBottom: '24px' },
  panelTitle:{ fontSize: '16px', fontWeight: '600', marginBottom: '20px', color: '#ececec' },
  table:     { width: '100%', borderCollapse: 'collapse' },
  th:        { padding: '10px 14px', textAlign: 'left', fontSize: '11px', color: '#555', fontWeight: '600', textTransform: 'uppercase', letterSpacing: '0.5px', borderBottom: '1px solid #1f1f1f' },
  td:        { padding: '12px 14px', fontSize: '13px', borderBottom: '1px solid #1a1a1a' },
  tr:        { transition: 'background 0.15s' },
  footerNote:{ textAlign: 'center', fontSize: '12px', color: '#333', marginTop: '8px' },
};

export default AdminDashboard;
