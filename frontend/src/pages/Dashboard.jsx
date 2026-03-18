import { useState, useEffect, useRef } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { io } from 'socket.io-client';
import { getResults } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';

export default function Dashboard() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [progress, setProgress] = useState(0);
  const [activity, setActivity] = useState('Initializing...');
  const [liveVulns, setLiveVulns] = useState([]);
  const [error, setError] = useState('');
  const socketRef = useRef(null);
  const pollRef = useRef(null);

  // Fetch initial state
  useEffect(() => {
    getResults(id)
      .then((r) => {
        setScan(r.data.scan);
        setProgress(r.data.scan.progress || 0);
        setActivity(r.data.scan.currentActivity || 'Running...');
        if (r.data.vulnerabilities?.length) setLiveVulns(r.data.vulnerabilities);
        if (r.data.scan.status === 'completed') navigate(`/results/${id}`);
      })
      .catch(() => setError('Could not load scan data.'));
  }, [id]);

  // Socket.IO for real-time events
  useEffect(() => {
    const socket = io(API_BASE, { transports: ['websocket', 'polling'] });
    socketRef.current = socket;

    socket.on('connect', () => socket.emit('join_scan', id));

    socket.on('scan_progress', (data) => {
      if (data.progress !== undefined) setProgress(data.progress);
      if (data.activity) setActivity(data.activity);
      if (data.status === 'completed') {
        setProgress(100);
        setActivity('Scan complete! Redirecting...');
        setTimeout(() => navigate(`/results/${id}`), 1500);
      }
      if (data.status === 'failed') setError(`Scan failed: ${data.activity}`);
      if (data.newVulnerability) {
        setLiveVulns((prev) => [{ ...data.newVulnerability, _id: Date.now() }, ...prev]);
      }
      if (data.endpointCount !== undefined) {
        setScan((prev) => prev ? { ...prev, endpointCount: data.endpointCount } : prev);
      }
    });

    // Fallback polling every 3s if WS fails
    pollRef.current = setInterval(() => {
      getResults(id)
        .then((r) => {
          setScan(r.data.scan);
          setProgress(r.data.scan.progress || 0);
          setActivity(r.data.scan.currentActivity || '');
          if (r.data.scan.status === 'completed') navigate(`/results/${id}`);
          if (r.data.vulnerabilities?.length) setLiveVulns(r.data.vulnerabilities);
        })
        .catch(() => {});
    }, 3000);

    return () => {
      socket.disconnect();
      clearInterval(pollRef.current);
    };
  }, [id]);

  return (
    <div className="animate-fade">
      <div className="page-header flex-between">
        <div>
          <h1 className="page-title">🔄 Scan in Progress</h1>
          <p className="page-subtitle" style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--primary)' }}>
            Scan ID: {id}
          </p>
        </div>
        <Link to="/" className="btn btn-secondary btn-sm">← New Scan</Link>
      </div>

      {error && <div className="alert alert-error mb-4">⚠️ {error}</div>}

      {/* Target URL */}
      {scan && (
        <div className="card mb-6">
          <div className="flex-between">
            <div>
              <p className="detail-label">Target URL</p>
              <p className="detail-value mono">{scan.targetUrl}</p>
            </div>
            <div style={{ textAlign: 'right' }}>
              <p className="detail-label">Started</p>
              <p className="detail-value">{new Date(scan.createdAt).toLocaleString()}</p>
            </div>
          </div>
        </div>
      )}

      {/* Progress */}
      <div className="card mb-6">
        <div className="card-header">
          <h2 className="card-title">Scan Progress</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="status-dot running" />
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Running</span>
          </div>
        </div>

        <div className="progress-container mb-4">
          <div className="progress-header">
            <span className="progress-label">Overall Progress</span>
            <span className="progress-pct">{progress}%</span>
          </div>
          <div className="progress-track">
            <div className="progress-bar" style={{ width: `${progress}%` }} />
          </div>
        </div>

        <div className="activity-log">{activity}</div>
      </div>

      {/* Stat cards */}
      {scan && (
        <div className="stat-cards mb-6">
          <div className="stat-card total">
            <div className="stat-value">{scan.endpointCount || scan.totalEndpoints || 0}</div>
            <div className="stat-label">Endpoints Discovered</div>
          </div>
          <div className="stat-card high">
            <div className="stat-value">{liveVulns.filter(v => v.severity === 'High' || v.severity === 'Critical').length}</div>
            <div className="stat-label">High/Critical</div>
          </div>
          <div className="stat-card medium">
            <div className="stat-value">{liveVulns.filter(v => v.severity === 'Medium').length}</div>
            <div className="stat-label">Medium</div>
          </div>
          <div className="stat-card low">
            <div className="stat-value">{liveVulns.filter(v => v.severity === 'Low').length}</div>
            <div className="stat-label">Low</div>
          </div>
        </div>
      )}

      {/* Live findings feed */}
      {liveVulns.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">⚡ Live Findings</h2>
            <span className="tag">{liveVulns.length} found</span>
          </div>
          <div className="table-container">
            <table className="vuln-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Endpoint</th>
                  <th>CVE</th>
                </tr>
              </thead>
              <tbody>
                {liveVulns.slice(0, 15).map((v, i) => (
                  <tr key={v._id || i} className="animate-slide">
                    <td><SeverityBadge severity={v.severity} /></td>
                    <td style={{ color: 'var(--text-primary)' }}>{v.type}</td>
                    <td className="url-cell">{v.endpoint || v.url}</td>
                    <td>{v.cveId ? <span className="cve-badge">{v.cveId}</span> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
