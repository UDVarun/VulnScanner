import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getResults, getReportUrl } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';

export default function Details() {
  const { scanId, vulnId } = useParams();
  const [vuln, setVuln] = useState(null);
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    getResults(scanId)
      .then((r) => {
        setScan(r.data.scan);
        const found = r.data.vulnerabilities.find((v) => v._id === vulnId);
        if (!found) setError('Vulnerability not found.');
        setVuln(found);
      })
      .catch(() => setError('Failed to load vulnerability details.'))
      .finally(() => setLoading(false));
  }, [scanId, vulnId]);

  if (loading) return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '300px' }}>
      <div className="spinner" style={{ width: 40, height: 40 }} />
    </div>
  );

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!vuln) return null;

  const cvssColor =
    vuln.cvssScore >= 9 ? 'var(--critical)'
    : vuln.cvssScore >= 7 ? 'var(--high)'
    : vuln.cvssScore >= 4 ? 'var(--medium)'
    : 'var(--low)';

  return (
    <div className="animate-fade">
      {/* Breadcrumb */}
      <div className="flex-gap mb-4" style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
        <Link to="/" style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>Home</Link>
        <span>/</span>
        <Link to={`/results/${scanId}`} style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>Results</Link>
        <span>/</span>
        <span style={{ color: 'var(--text-secondary)' }}>Vulnerability Detail</span>
      </div>

      {/* Header */}
      <div className="page-header flex-between">
        <div className="flex-gap">
          <SeverityBadge severity={vuln.severity} />
          <h1 className="page-title" style={{ margin: 0 }}>{vuln.type}</h1>
        </div>
        <div className="flex-gap">
          <Link to={`/results/${scanId}`} className="btn btn-secondary btn-sm">← Back to Results</Link>
          <a href={getReportUrl(scanId)} target="_blank" rel="noreferrer" className="btn btn-primary btn-sm">
            📄 PDF Report
          </a>
        </div>
      </div>

      {/* CVSS Score Hero */}
      <div className="card mb-6" style={{ borderColor: cvssColor, background: 'var(--bg-card)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '32px', flexWrap: 'wrap' }}>
          <div style={{ textAlign: 'center', minWidth: 100 }}>
            <div style={{ fontSize: '3rem', fontWeight: 800, color: cvssColor, fontFamily: 'JetBrains Mono, monospace', lineHeight: 1 }}>
              {vuln.cvssScore || 'N/A'}
            </div>
            <div className="detail-label" style={{ marginTop: 4 }}>CVSS Score</div>
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ marginBottom: 8 }}>
              <span className="cve-badge" style={{ fontSize: '0.9rem', padding: '4px 12px' }}>{vuln.cveId || 'N/A'}</span>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.6 }}>
              {vuln.cveDescription || 'No CVE description available.'}
            </p>
            {vuln.cvssVector && vuln.cvssVector !== 'N/A' && (
              <div style={{ marginTop: 8 }}>
                <span className="tag">{vuln.cvssVector}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Details grid */}
      <div className="grid-2 mb-6">
        <div className="card">
          <div className="card-header"><h2 className="card-title">🔍 Technical Details</h2></div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="detail-item">
              <span className="detail-label">Endpoint</span>
              <span className="detail-value mono">{vuln.endpoint}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Parameter</span>
              <span className="detail-value">{vuln.parameter || 'N/A'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">HTTP Method</span>
              <span className="detail-value">{vuln.method || 'GET'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Confidence</span>
              <span className="detail-value" style={{
                color: vuln.confidence === 'High' ? 'var(--low)' : vuln.confidence === 'Medium' ? 'var(--medium)' : 'var(--text-muted)'
              }}>
                {vuln.confidence}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Detected At</span>
              <span className="detail-value">{new Date(vuln.timestamp).toLocaleString()}</span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><h2 className="card-title">💉 Attack Details</h2></div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="detail-item">
              <span className="detail-label">Payload Used</span>
              <span className="detail-value payload">{vuln.payload || 'N/A'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-label">Evidence</span>
              <span className="detail-value evidence">{vuln.evidence || 'No evidence captured.'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recommendation */}
      <div className="card" style={{ borderColor: 'var(--low)', borderLeftWidth: 4 }}>
        <div className="card-header">
          <h2 className="card-title">🛠 Remediation Recommendation</h2>
        </div>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          {vuln.recommendation || 'Consult OWASP guidelines for remediation of this vulnerability type.'}
        </p>

        <div className="mt-4 flex-gap">
          <a
            href={`https://owasp.org/www-community/attacks/${vuln.type.replace(/\s+/g, '_')}`}
            target="_blank" rel="noreferrer"
            className="btn btn-secondary btn-sm"
          >
            📖 OWASP Reference
          </a>
          {vuln.cveId && vuln.cveId !== 'N/A' && !vuln.cveId.startsWith('CWE') && (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`}
              target="_blank" rel="noreferrer"
              className="btn btn-secondary btn-sm"
            >
              🔗 NVD Entry
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
