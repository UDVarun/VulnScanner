import React from 'react';

export default function CleanScanPanel({ endpoints, endpointCount, target, summary, completedAt }) {
  const [searchQuery, setSearchQuery] = React.useState('');
  const [methodFilter, setMethodFilter] = React.useState('ALL');
  const [sortBy, setSortBy] = React.useState('url'); // 'url' | 'status' | 'forms' | 'params'
  const [sortDir, setSortDir] = React.useState('asc');

  // Filter and sort endpoints
  const filtered = endpoints
    .filter(ep => {
      const matchesSearch = ep.url.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesMethod = methodFilter === 'ALL' || ep.method === methodFilter;
      return matchesSearch && matchesMethod;
    })
    .sort((a, b) => {
      let valA = a[sortBy] ?? '';
      let valB = b[sortBy] ?? '';
      if (typeof valA === 'string') valA = valA.toLowerCase();
      if (typeof valB === 'string') valB = valB.toLowerCase();
      
      if (valA < valB) return sortDir === 'asc' ? -1 : 1;
      if (valA > valB) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

  const handleSort = (col) => {
    if (sortBy === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(col);
      setSortDir('asc');
    }
  };

  const uniqueMethods = ['ALL', ...new Set(endpoints.map(ep => ep.method || 'GET'))];

  return (
    <div className="clean-scan-panel">

      {/* ── CLEAN RESULT BANNER ── */}
      <div className="clean-banner">
        {/* Green shield / checkmark icon */}
        <div className="clean-icon">
          <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
            <circle cx="32" cy="32" r="30" fill="#166534" fillOpacity="0.15" stroke="#22c55e" strokeWidth="2"/>
            <path d="M20 32l8 8 16-16" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>
        <div className="clean-text">
          <h2>No Vulnerabilities Found</h2>
          <p>
            VulnScanner crawled <strong>{target}</strong> and tested{' '}
            <strong>{endpointCount}</strong> endpoint{endpointCount !== 1 ? 's' : ''}.
            No exploitable vulnerabilities were detected across all tested categories.
          </p>
          {summary?.info > 0 && (
            <p className="info-note">
              ℹ️ {summary.info} informational notice{summary.info !== 1 ? 's' : ''} were noted
              (low-priority headers on trusted infrastructure). These are not vulnerabilities.
            </p>
          )}
        </div>
      </div>

      {/* ── SCAN SUMMARY STATS ── */}
      <div className="clean-stats-row">
        <div className="clean-stat">
          <span className="stat-value">{endpointCount}</span>
          <span className="stat-label">Endpoints Crawled</span>
        </div>
        <div className="clean-stat">
          <span className="stat-value">{endpoints.filter(e => (e.forms ?? 0) > 0).length}</span>
          <span className="stat-label">Pages with Forms</span>
        </div>
        <div className="clean-stat">
          <span className="stat-value">{endpoints.filter(e => (e.params ?? 0) > 0).length}</span>
          <span className="stat-label">Parametrised URLs</span>
        </div>
        <div className="clean-stat">
          <span className="stat-value">
            {endpoints.filter(e => e.status >= 200 && e.status < 300).length}
          </span>
          <span className="stat-label">200 OK Responses</span>
        </div>
        <div className="clean-stat">
          <span className="stat-value">
            {endpoints.filter(e => e.status >= 300 && e.status < 400).length}
          </span>
          <span className="stat-label">Redirects</span>
        </div>
        <div className="clean-stat">
          <span className="stat-value">
            {endpoints.filter(e => e.status >= 400).length}
          </span>
          <span className="stat-label">Error Responses</span>
        </div>
      </div>

      {/* ── ENDPOINTS TABLE ── */}
      <div className="endpoints-section">
        <div className="endpoints-header">
          <h3>Endpoints Discovered ({endpointCount})</h3>
          <p className="endpoints-subheader">
            All URLs crawled and tested during the scan. Click any column header to sort.
          </p>
        </div>

        {/* Controls: search + method filter */}
        <div className="endpoints-controls">
          <input
            type="text"
            placeholder="Search endpoints..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="endpoint-search"
          />
          <span className="method-filters">
            {uniqueMethods.map(method => (
              <button
                key={method}
                onClick={() => setMethodFilter(method)}
                className={`method-btn ${methodFilter === method ? 'active' : ''}`}
              >
                {method}
              </button>
            ))}
          </span>
          <span className="showing-count">
            Showing {filtered.length} of {endpointCount}
          </span>
        </div>

        {/* Endpoints table */}
        {filtered.length === 0 ? (
          <div className="no-endpoints-msg">
            {endpointCount === 0
              ? 'The crawler did not discover any endpoints. The target may have blocked crawling.'
              : 'No endpoints match your search or filter.'}
          </div>
        ) : (
          <div className="endpoints-table-wrapper">
            <table className="endpoints-table">
              <thead>
                <tr>
                  <th className="col-num">#</th>
                  <th
                    className={`col-url sortable ${sortBy === 'url' ? 'sorted' : ''}`}
                    onClick={() => handleSort('url')}
                  >
                    URL {sortBy === 'url' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                  <th
                    className={`col-method sortable ${sortBy === 'method' ? 'sorted' : ''}`}
                    onClick={() => handleSort('method')}
                  >
                    Method {sortBy === 'method' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                  <th
                    className={`col-status sortable ${sortBy === 'status' ? 'sorted' : ''}`}
                    onClick={() => handleSort('status')}
                  >
                    Status {sortBy === 'status' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                  <th
                    className={`col-forms sortable ${sortBy === 'forms' ? 'sorted' : ''}`}
                    onClick={() => handleSort('forms')}
                  >
                    Forms {sortBy === 'forms' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                  <th
                    className={`col-params sortable ${sortBy === 'params' ? 'sorted' : ''}`}
                    onClick={() => handleSort('params')}
                  >
                    Params {sortBy === 'params' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((ep, i) => (
                  <tr key={ep.url + i} className="endpoint-row">
                    <td className="col-num">{i + 1}</td>
                    <td className="col-url">
                      <a
                        href={ep.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="endpoint-link"
                        title={ep.url}
                      >
                        {ep.url.length > 80 ? ep.url.substring(0, 77) + '...' : ep.url}
                      </a>
                    </td>
                    <td className="col-method">
                      <span className={`method-badge method-${(ep.method || 'GET').toLowerCase()}`}>
                        {ep.method || 'GET'}
                      </span>
                    </td>
                    <td className="col-status">
                      <span className={`status-badge status-${Math.floor((ep.status || 0) / 100)}xx`}>
                        {ep.status || '—'}
                      </span>
                    </td>
                    <td className="col-forms">{ep.forms ?? 0}</td>
                    <td className="col-params">{ep.params ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
