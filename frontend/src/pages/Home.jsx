import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { startScan, getScans } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

export default function Home() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [recentScans, setRecentScans] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    getScans()
      .then((r) => setRecentScans(r.data.slice(0, 6)))
      .catch(() => {});
  }, []);

  const handleScan = async (e) => {
    e.preventDefault();
    setError('');
    if (!url.trim()) { setError('Please enter a target URL.'); return; }

    let fullUrl = url.trim();
    if (!/^https?:\/\//i.test(fullUrl)) fullUrl = 'http://' + fullUrl;

    setLoading(true);
    try {
      const res = await startScan(fullUrl);
      navigate(`/dashboard/${res.data.scanId}`);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  const statusLabel = (s) => {
    if (s === 'completed') return <span style={{color: 'var(--low)'}}>● Completed</span>;
    if (s === 'running') return <span style={{color: 'var(--primary)'}}>● Running</span>;
    if (s === 'failed') return <span style={{color: 'var(--high)'}}>● Failed</span>;
    return <span style={{color: 'var(--medium)'}}>● Queued</span>;
  };

  return (
    <div className="animate-fade">
      {/* ── Hero ── */}
      <div className="hero">
        <div className="hero-glow" />
        <div className="hero-label">⚡ Powered by Real HTTP Analysis</div>
        <h1>Web Application<br />Vulnerability Scanner</h1>
        <p>
          Discover SQL Injection, XSS, missing security headers, and more.
          Every finding is backed by real HTTP request analysis and mapped to NVD CVE data.
        </p>

        {/* ── Scan Form ── */}
        <form className="scan-form" onSubmit={handleScan}>
          <div className="scan-form-inner">
            <span style={{ fontSize: '1.1rem' }}>🔍</span>
            <input
              id="scan-url-input"
              className="scan-form-input"
              type="text"
              placeholder="https://target.example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
              autoFocus
            />
            <button
              id="start-scan-btn"
              type="submit"
              className="btn btn-primary btn-lg"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="spinner" style={{ width: 16, height: 16 }} />
                  Starting...
                </>
              ) : (
                '⚡ Scan Now'
              )}
            </button>
          </div>

          {error && (
            <div className="alert alert-error mt-4" role="alert">
              ⚠️ {error}
            </div>
          )}
        </form>

        {/* ── Feature chips ── */}
        <div className="flex-gap" style={{ justifyContent: 'center', gap: '10px' }}>
          {['SQL Injection Detection', 'XSS Analysis', 'CVE Mapping', 'PDF Reports', 'Real-time Progress'].map((f) => (
            <span key={f} className="tag">{f}</span>
          ))}
        </div>
      </div>

      {/* ── Recent Scans ── */}
      {recentScans.length > 0 && (
        <div className="mt-6">
          <p className="section-title">Recent Scans</p>
          <div className="scans-grid">
            {recentScans.map((scan) => (
              <Link
                to={scan.status === 'completed' ? `/results/${scan._id}` : `/dashboard/${scan._id}`}
                key={scan._id}
                className="scan-card"
              >
                <div className="scan-card-url">{scan.targetUrl}</div>
                <div className="scan-card-meta">
                  {new Date(scan.createdAt).toLocaleString()} · {statusLabel(scan.status)}
                </div>
                <div className="flex-gap">
                  {scan.summary?.total > 0 && (
                    <>
                      {scan.summary.critical > 0 && <SeverityBadge severity="Critical" />}
                      {scan.summary.high > 0 && <SeverityBadge severity="High" />}
                      {scan.summary.medium > 0 && <SeverityBadge severity="Medium" />}
                      {scan.summary.low > 0 && <SeverityBadge severity="Low" />}
                      <span className="tag">{scan.summary.total} total</span>
                    </>
                  )}
                  {scan.summary?.total === 0 && scan.status === 'completed' && (
                    <span style={{ color: 'var(--low)', fontSize: '0.8rem' }}>✅ No vulnerabilities found</span>
                  )}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
