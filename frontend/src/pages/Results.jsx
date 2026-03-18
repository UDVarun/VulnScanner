import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { getResults, getReportUrl } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import CleanScanPanel from '../components/CleanScanPanel';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'Critical', 'High', 'Medium', 'Low', 'Info'];
const SEVERITY_COLORS = {
  Critical: '#ff2222',
  High: '#ff4444',
  Medium: '#ffaa00',
  Low: '#00cc66',
  Info: '#6688cc',
  critical: '#ff2222',
  high: '#ff4444',
  medium: '#ffaa00',
  low: '#00cc66',
  info: '#6688cc',
};

export default function Results() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [vulns, setVulns] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [typeFilter, setTypeFilter] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    getResults(id)
      .then((r) => {
        setScan(r.data.scan);
        const sorted = [...r.data.vulnerabilities].sort(
          (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
        );
        setVulns(sorted);
        setFiltered(sorted);
      })
      .catch(() => setError('Failed to load results.'))
      .finally(() => setLoading(false));
  }, [id]);

  // Apply filters
  useEffect(() => {
    let result = [...vulns];
    if (severityFilter !== 'All') result = result.filter((v) => (v.severity || '').toLowerCase() === severityFilter.toLowerCase());
    if (typeFilter !== 'All') result = result.filter((v) => v.type === typeFilter);

    // Auto-fallback if the filtered list is empty but we have vulns overall
    if (result.length === 0 && vulns.length > 0 && (severityFilter !== 'All' || typeFilter !== 'All')) {
      if (severityFilter !== 'All' && vulns.filter(v => (v.severity || '').toLowerCase() === severityFilter.toLowerCase()).length === 0) {
        setSeverityFilter('All');
      }
    }

    setFiltered(result);
  }, [severityFilter, typeFilter, vulns]);

  const vulnTypes = ['All', ...new Set(vulns.map((v) => v.type))];
  const severities = ['All', ...SEVERITY_ORDER.filter((s) => vulns.some((v) => v.severity === s))];

  // Pie chart data
  const pieData = SEVERITY_ORDER
    .map((s) => ({ name: s, value: vulns.filter((v) => v.severity === s).length }))
    .filter((d) => d.value > 0);

  // Derive clean scan state
  const summary = scan?.summary || {};
  const hasRealVulnerabilities = (
    (summary.critical || 0) +
    (summary.high || 0) +
    (summary.medium || 0) +
    (summary.low || 0)
  ) > 0;
  const endpoints = scan?.endpoints || [];
  const endpointCount = scan?.endpointCount || scan?.totalEndpoints || endpoints.length;

  if (loading) return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '300px' }}>
      <div className="spinner" style={{ width: 40, height: 40 }} />
    </div>
  );

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!scan) return null;

  return (
    <div className="animate-fade">
      {/* Header */}
      <div className="page-header flex-between">
        <div>
          <h1 className="page-title">📊 Scan Results</h1>
          <p className="page-subtitle" style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--primary)', fontSize: '0.85rem' }}>
            {scan.targetUrl}
          </p>
        </div>
        <div className="flex-gap">
          <Link to="/" className="btn btn-secondary btn-sm">← New Scan</Link>
          <a href={getReportUrl(id)} target="_blank" rel="noreferrer" className="btn btn-primary btn-sm">
            📄 Download PDF
          </a>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="stat-cards mb-6">
        <div className="stat-card critical">
          <div className="stat-value">{scan.summary?.critical || 0}</div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat-card high">
          <div className="stat-value">{scan.summary?.high || 0}</div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-value">{scan.summary?.medium || 0}</div>
          <div className="stat-label">Medium</div>
        </div>
        <div className="stat-card low">
          <div className="stat-value">{scan.summary?.low || 0}</div>
          <div className="stat-label">Low</div>
        </div>
        <div className="stat-card info" style={{ borderTop: '3px solid #6b7280', color: '#9ca3af' }}>
          <div className="stat-value" style={{ color: '#9ca3af' }}>{scan.summary?.info || 0}</div>
          <div className="stat-label">Info</div>
        </div>
        <div className="stat-card total">
          <div className="stat-value">{scan.summary?.total || 0}</div>
          <div className="stat-label">Total</div>
        </div>
      </div>

      {/* Chart + Info */}
      <div className="grid-2 mb-6">
        <div className="card">
          <div className="card-header"><h2 className="card-title">Risk Distribution</h2></div>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}>
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={SEVERITY_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }}
                />
                <Legend
                  formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--low)' }}>✅ No vulnerabilities</div>
          )}
        </div>

        <div className="card">
          <div className="card-header"><h2 className="card-title">Scan Details</h2></div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {[
              ['Status', <span style={{ color: 'var(--low)' }}>✅ {scan.status}</span>],
              ['Endpoints', endpointCount || 'N/A'],
              ['Completed', scan.completedAt ? new Date(scan.completedAt).toLocaleString() : 'N/A'],
              ['Duration', scan.completedAt ? `${Math.round((new Date(scan.completedAt) - new Date(scan.createdAt)) / 1000)}s` : 'N/A'],
            ].map(([label, value]) => (
              <div key={label} className="detail-item">
                <span className="detail-label">{label}</span>
                <span className="detail-value">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Clean Scan Panel — shown when no real vulns */}
      {!hasRealVulnerabilities && (
        <CleanScanPanel
          endpoints={endpoints}
          endpointCount={endpointCount}
          target={scan.targetUrl}
          summary={scan.summary}
          completedAt={scan.completedAt}
        />
      )}

      {/* Vulnerability Table — shown only when real vulns exist */}
      {hasRealVulnerabilities && (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Vulnerabilities ({filtered.length})</h2>
          </div>

          {/* Severity filter */}
          <div className="filter-bar mb-4">
            {severities.map((s) => (
              <button
                key={s}
                className={`filter-btn ${severityFilter === s ? (s === 'All' ? 'active' : `active-${s.toLowerCase()}`) : ''}`}
                onClick={() => setSeverityFilter(s)}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Type filter */}
          <div className="filter-bar mb-4">
            {vulnTypes.map((t) => (
              <button
                key={t}
                className={`filter-btn ${typeFilter === t ? 'active' : ''}`}
                onClick={() => setTypeFilter(t)}
              >
                {t}
              </button>
            ))}
          </div>

          {filtered.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">✅</div>
              <h3>No vulnerabilities found</h3>
              <p>No issues match the current filters.</p>
            </div>
          ) : (
            <div className="table-container">
              <table className="vuln-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Endpoint</th>
                    <th>Param</th>
                    <th>CVE ID</th>
                    <th>CVSS</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((v, i) => (
                    <tr key={v._id} onClick={() => navigate(`/details/${id}/${v._id}`)}>
                      <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                      <td><SeverityBadge severity={v.severity} /></td>
                      <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{v.type}</td>
                      <td className="url-cell">{v.endpoint}</td>
                      <td><span className="tag">{v.parameter || 'N/A'}</span></td>
                      <td>{v.cveId && v.cveId !== 'N/A' ? <span className="cve-badge">{v.cveId}</span> : <span style={{ color: 'var(--text-muted)' }}>—</span>}</td>
                      <td style={{ color: v.cvssScore >= 7 ? 'var(--high)' : v.cvssScore >= 4 ? 'var(--medium)' : 'var(--low)', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
                        {v.cvssScore || '—'}
                      </td>
                      <td style={{ color: v.confidence === 'High' ? 'var(--low)' : v.confidence === 'Medium' ? 'var(--medium)' : 'var(--text-muted)' }}>
                        {v.confidence}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
