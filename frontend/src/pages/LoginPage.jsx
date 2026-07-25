import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const API = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api/v1';

export default function LoginPage() {
  const [username, setUsername]   = useState('');
  const [password, setPassword]   = useState('');
  const [error, setError]         = useState('');
  const [loading, setLoading]     = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res  = await fetch(`${API}/auth/login`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Login failed');
      localStorage.setItem('ids_token',    data.access_token);
      localStorage.setItem('ids_username', data.username);
      localStorage.setItem('ids_role',     data.role);
      navigate('/admin');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.page}>
      {/* Background grid */}
      <div style={styles.grid} />

      <div style={styles.card}>
        {/* Logo / header */}
        <div style={styles.logoWrap}>
          <div style={styles.logoIcon}>🛡️</div>
          <h1 style={styles.title}>IDS Admin Portal</h1>
          <p style={styles.subtitle}>CNN-LSTM Intrusion Detection System</p>
        </div>

        {/* Badge */}
        <div style={styles.badge}>
          <span style={styles.dot} />
          Secure Access Only
        </div>

        {/* Form */}
        <form onSubmit={handleLogin} style={styles.form}>
          <div style={styles.fieldWrap}>
            <label style={styles.label}>Username or Email</label>
            <input
              id="ids-username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="admin"
              required
              autoComplete="username"
              style={styles.input}
              onFocus={e => e.target.style.borderColor = '#10a37f'}
              onBlur={e  => e.target.style.borderColor = '#333'}
            />
          </div>

          <div style={styles.fieldWrap}>
            <label style={styles.label}>Password</label>
            <input
              id="ids-password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              autoComplete="current-password"
              style={styles.input}
              onFocus={e => e.target.style.borderColor = '#10a37f'}
              onBlur={e  => e.target.style.borderColor = '#333'}
            />
          </div>

          {error && (
            <div style={styles.errorBox}>
              <span>⚠️</span> {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{ ...styles.btn, opacity: loading ? 0.7 : 1 }}
          >
            {loading ? 'Authenticating…' : '🔐 Sign In to Dashboard'}
          </button>
        </form>

        {/* Default creds hint */}
        <div style={styles.hint}>
          Default credentials: <code style={styles.code}>admin</code> / <code style={styles.code}>admin123</code>
        </div>

        <p style={styles.footer}>
          All access attempts are logged and monitored.
        </p>
      </div>
    </div>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────────
const styles = {
  page: {
    minHeight: '100vh',
    backgroundColor: '#0a0a0a',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontFamily: "'Inter', sans-serif",
    position: 'relative',
    overflow: 'hidden',
  },
  grid: {
    position: 'absolute', inset: 0,
    backgroundImage: `
      linear-gradient(rgba(16,163,127,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(16,163,127,0.04) 1px, transparent 1px)`,
    backgroundSize: '40px 40px',
  },
  card: {
    position: 'relative',
    background: 'linear-gradient(135deg, #141414 0%, #1a1a1a 100%)',
    border: '1px solid rgba(16,163,127,0.25)',
    borderRadius: '20px',
    padding: '48px 40px',
    width: '100%',
    maxWidth: '420px',
    boxShadow: '0 0 60px rgba(16,163,127,0.08), 0 24px 48px rgba(0,0,0,0.5)',
  },
  logoWrap: { textAlign: 'center', marginBottom: '28px' },
  logoIcon: { fontSize: '48px', marginBottom: '12px' },
  title: {
    fontSize: '24px', fontWeight: '700',
    color: '#ececec', margin: '0 0 6px',
    letterSpacing: '-0.5px',
  },
  subtitle: { fontSize: '13px', color: '#666', margin: 0 },
  badge: {
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    gap: '8px', marginBottom: '32px',
    background: 'rgba(16,163,127,0.08)',
    border: '1px solid rgba(16,163,127,0.2)',
    borderRadius: '999px', padding: '6px 16px',
    fontSize: '12px', color: '#10a37f', fontWeight: '600',
  },
  dot: {
    width: '7px', height: '7px', borderRadius: '50%',
    backgroundColor: '#10a37f',
    boxShadow: '0 0 6px #10a37f',
    animation: 'pulse 2s infinite',
    display: 'inline-block',
  },
  form:      { display: 'flex', flexDirection: 'column', gap: '20px' },
  fieldWrap: { display: 'flex', flexDirection: 'column', gap: '8px' },
  label:     { fontSize: '13px', color: '#9b9b9b', fontWeight: '500' },
  input: {
    background: '#0f0f0f', border: '1px solid #333',
    borderRadius: '10px', padding: '12px 14px',
    color: '#ececec', fontSize: '14px',
    outline: 'none', transition: 'border-color 0.2s',
    width: '100%', boxSizing: 'border-box',
  },
  errorBox: {
    background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
    borderRadius: '8px', padding: '10px 14px',
    color: '#ef4444', fontSize: '13px',
    display: 'flex', alignItems: 'center', gap: '8px',
  },
  btn: {
    background: 'linear-gradient(135deg, #10a37f, #0d8f6e)',
    border: 'none', borderRadius: '10px',
    padding: '13px', color: '#fff',
    fontSize: '14px', fontWeight: '600',
    cursor: 'pointer', marginTop: '4px',
    transition: 'transform 0.1s, box-shadow 0.2s',
    boxShadow: '0 4px 20px rgba(16,163,127,0.3)',
  },
  hint: {
    marginTop: '24px', textAlign: 'center',
    fontSize: '12px', color: '#555',
    background: 'rgba(255,255,255,0.03)',
    border: '1px solid #222', borderRadius: '8px',
    padding: '10px 14px',
  },
  code: {
    background: '#222', borderRadius: '4px',
    padding: '2px 6px', fontFamily: 'monospace',
    color: '#10a37f',
  },
  footer: {
    marginTop: '20px', textAlign: 'center',
    fontSize: '11px', color: '#444',
  },
};
