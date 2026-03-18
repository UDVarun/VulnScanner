/**
 * Scanner Engine
 * Core scanning logic: sends baseline + injected requests and detects vulnerabilities.
 * Handles SQLi, XSS, Security Headers, Auth Bypass, Path Traversal, Header Injection.
 */
const axios = require('axios');
const { getPayloads } = require('./payloadEngine');
const { analyze } = require('./analyzerEngine');

const TRUSTED_DOMAINS = new Set([
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
  'instagram.com', 'linkedin.com', 'github.com', 'amazon.com',
  'microsoft.com', 'apple.com', 'wikipedia.org', 'reddit.com',
  'netflix.com', 'yahoo.com', 'bing.com', 'live.com', 'office.com',
  'cloudflare.com', 'akamai.com', 'fastly.com', 'shopify.com',
  'wordpress.com', 'blogger.com', 'tumblr.com', 'medium.com',
  'stackoverflow.com', 'mozilla.org', 'w3.org', 'adobe.com'
]);

function extractHostname(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return '';
  }
}

function isTrustedDomain(url) {
  const hostname = extractHostname(url);
  // Check exact match and parent domain match
  for (const trusted of TRUSTED_DOMAINS) {
    if (hostname === trusted || hostname.endsWith('.' + trusted)) return true;
  }
  return false;
}

function isHTTPS(url) {
  return url.trim().toLowerCase().startsWith('https://');
}

/**
 * Compute adjusted severity and confidence for a header finding.
 * Returns { severity, cvss, confidence, suppress }
 */
function scoreHeaderFinding({ targetUrl, header, baseSeverity, baseCvss, baseConfidence, signals = 1 }) {
  const trusted = isTrustedDomain(targetUrl);
  const secure = isHTTPS(targetUrl);

  // Trusted domain → always informational
  if (trusted) {
    return { severity: 'info', cvss: 0, confidence: baseConfidence * 0.4, suppress: false };
  }

  // Low confidence → suppress entirely (do not save to DB)
  if (baseConfidence < 0.4) {
    return { severity: 'info', cvss: 0, confidence: baseConfidence, suppress: true };
  }

  // Only 1 signal and HTTPS → downgrade
  if (signals < 2 && secure) {
    const newSeverity = baseSeverity === 'Medium' ? 'Low' : baseSeverity === 'High' ? 'Medium' : 'Info';
    return { severity: newSeverity.toLowerCase(), cvss: Math.max(0, baseCvss - 2.0), confidence: baseConfidence * 0.75, suppress: false };
  }

  // Only 1 signal (HTTP) → keep but lower confidence
  if (signals < 2) {
    return { severity: baseSeverity.toLowerCase(), cvss: baseCvss, confidence: baseConfidence * 0.85, suppress: false };
  }

  // 2+ signals → full severity (no change)
  return { severity: baseSeverity.toLowerCase(), cvss: baseCvss, confidence: baseConfidence, suppress: false };
}

const headerCvssMap = {
  'Content-Security-Policy': 6.1,
  'Strict-Transport-Security': 5.9,
  'X-Frame-Options': 5.4,
  'X-Content-Type-Options': 4.3,
  'Referrer-Policy': 3.1,
  'Permissions-Policy': 3.0,
  'X-XSS-Protection': 4.0,
  'Cache-Control': 3.5
};

const headerRecommendations = {
  'Content-Security-Policy': 'Add a Content-Security-Policy header to restrict resource loading and prevent XSS attacks.',
  'Strict-Transport-Security': 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  'X-Frame-Options': 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.',
  'X-Content-Type-Options': 'Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.',
  'Referrer-Policy': 'Add Referrer-Policy: strict-origin-when-cross-origin to control referrer information.',
  'Permissions-Policy': 'Add Permissions-Policy header to restrict browser feature access.',
  'X-XSS-Protection': 'Add X-XSS-Protection: 1; mode=block (legacy browsers support).',
  'Cache-Control': 'Add Cache-Control: no-store for sensitive pages.'
};

const REQUEST_TIMEOUT = 15000;
const DELAY_BETWEEN_REQUESTS = 20; // ms — fast timing

const DEFAULT_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
  'Connection': 'keep-alive',
};

// Security headers to check
const REQUIRED_SECURITY_HEADERS = [
  {
    name: 'x-frame-options',
    description: 'X-Frame-Options',
    recommendation:
      'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks.',
  },
  {
    name: 'content-security-policy',
    description: 'Content-Security-Policy',
    recommendation:
      'Implement a strong Content-Security-Policy header to prevent XSS and data injection attacks.',
  },
  {
    name: 'x-xss-protection',
    description: 'X-XSS-Protection',
    recommendation:
      'Add X-XSS-Protection: 1; mode=block to enable browser-level XSS filtering.',
  },
  {
    name: 'strict-transport-security',
    description: 'Strict-Transport-Security (HSTS)',
    recommendation:
      'Implement HSTS with a minimum max-age of 31536000 (1 year) to enforce HTTPS.',
  },
  {
    name: 'x-content-type-options',
    description: 'X-Content-Type-Options',
    recommendation:
      'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing attacks.',
  },
];

// Protected-looking paths for auth bypass detection
const AUTH_PATHS = [
  '/admin', '/admin/', '/dashboard', '/api/admin', '/admin/dashboard',
  '/admin/users', '/console', '/manage', '/management', '/wp-admin',
  '/phpmyadmin', '/cpanel', '/webmail',
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Make an HTTP request and capture timing
 */
async function makeRequest(url, options = {}) {
  const start = Date.now();
  try {
    const response = await axios({
      url,
      method: options.method || 'GET',
      headers: { ...DEFAULT_HEADERS, ...(options.headers || {}) },
      params: options.params || {},
      data: options.data || {},
      timeout: REQUEST_TIMEOUT,
      validateStatus: () => true,
      maxRedirects: 3,
    });
    return {
      status: response.status,
      body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data),
      headers: response.headers,
      responseTime: Date.now() - start,
    };
  } catch (err) {
    return {
      status: 0,
      body: err.message,
      headers: {},
      responseTime: Date.now() - start,
      error: true,
    };
  }
}

/**
 * Inject payload into query params and return modified URL
 */
function injectIntoQueryParams(url, paramName, payload) {
  try {
    const u = new URL(url);
    const params = new URLSearchParams(u.search);
    if (params.has(paramName)) {
      params.set(paramName, payload);
    } else {
      params.set(paramName, payload);
    }
    u.search = params.toString();
    return u.href;
  } catch {
    return url + (url.includes('?') ? '&' : '?') + `${paramName}=${encodeURIComponent(payload)}`;
  }
}

/**
 * Check for missing security headers on an endpoint
 */
async function checkSecurityHeaders(endpoint) {
  const findings = [];
  const response = await makeRequest(endpoint.url);

  if (response.error || response.status >= 400 || response.status === 0) return findings;

  for (const headerDef of REQUIRED_SECURITY_HEADERS) {
    const headerVal = response.headers[headerDef.name];
    if (headerVal === undefined || headerVal === null || headerVal === '') {
      const scored = scoreHeaderFinding({
        targetUrl: endpoint.url,
        header: headerDef.description,
        baseSeverity: 'Medium',
        baseCvss: headerCvssMap[headerDef.description] || 5.3,
        baseConfidence: 0.65,
        signals: 1
      });

      if (!scored.suppress) {
        findings.push({
          type: 'Missing Security Header',
          severity: scored.severity,
          cvssScore: scored.cvss,
          confidence: scored.confidence < 0.5 ? 'Low' : scored.confidence < 0.8 ? 'Medium' : 'High', // map to enum just in case
          endpoint: endpoint.url,
          parameter: headerDef.description,
          payload: 'N/A',
          evidence: `Header "${headerDef.description}" was not present in the HTTP response.`,
          recommendation: headerRecommendations[headerDef.description] || `Add the ${headerDef.description} header to all responses.`,
          suppress: scored.suppress
        });
      }
    }
  }

  return findings;
}

/**
 * Check for auth bypass by accessing admin paths
 */
async function checkAuthBypass(endpoint) {
  const findings = [];
  const base = new URL(endpoint.url);
  const origin = base.origin;

  // First check if the site blindly returns 200 for random non-existent paths (soft 404s)
  try {
    const randomPathResp = await makeRequest(origin + '/nonexistent-random-path-' + Date.now());
    if (
      randomPathResp.status === 200 &&
      !randomPathResp.body.toLowerCase().includes('not found') &&
      !randomPathResp.body.toLowerCase().includes('404')
    ) {
      // Site likely returns 200 for everything, any auth bypass check will be a false positive
      return [];
    }
  } catch {
    // ignore
  }

  for (const path of AUTH_PATHS) {
    const targetUrl = origin + path;
    try {
      const response = await makeRequest(targetUrl);
      await sleep(DELAY_BETWEEN_REQUESTS);

      // If we get a 200 on an admin-looking path with no auth headers, flag it
      if (
        response.status === 200 &&
        !response.error &&
        response.body.length > 200 &&
        !response.body.toLowerCase().includes('login') &&
        !response.body.toLowerCase().includes('sign in') &&
        !response.body.toLowerCase().includes('unauthorized')
      ) {
        const signals = isHTTPS(targetUrl) ? 1 : 2;
        const scored = scoreHeaderFinding({
          targetUrl,
          header: 'auth-bypass',
          baseSeverity: 'High',
          baseCvss: 7.5,
          baseConfidence: 0.7,
          signals
        });

        if (!scored.suppress) {
          findings.push({
            type: 'Auth Bypass',
            severity: scored.severity,
            cvssScore: scored.cvss,
            endpoint: targetUrl,
            parameter: 'Path Access',
            payload: path,
            evidence: `Protected path accessible without authentication (HTTP ${response.status}, ${response.body.length} bytes)`,
            confidence: scored.confidence < 0.5 ? 'Low' : scored.confidence < 0.8 ? 'Medium' : 'High',
            recommendation: 'Implement proper authentication and authorization checks on all administrative endpoints.',
            suppress: scored.suppress
          });
        }
        // Only report once per base origin
        break;
      }
    } catch {
      // Ignore errors on auth bypass checks
    }
  }

  return findings;
}

async function testParameter(endpoint, paramName, vulnType) {
  const payloads = getPayloads(vulnType);

  // Baseline request
  const baseline = await makeRequest(endpoint.url, { method: endpoint.method });

  const promises = payloads.map(async (payloadObj) => {
    const payload = payloadObj.value;

    let injectedUrl = endpoint.url;
    let requestOptions = { method: endpoint.method };

    if (endpoint.method === 'GET') {
      injectedUrl = injectIntoQueryParams(endpoint.url, paramName, payload);
    } else {
      // POST: inject into form data
      requestOptions.data = { [paramName]: payload };
      requestOptions.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    }

    const injected = await makeRequest(injectedUrl, requestOptions);
    const result = analyze(vulnType, payload, baseline, injected);

    if (result.vulnerable && result.confidence !== 'Low') {
      return {
        type: vulnType,
        endpoint: endpoint.url,
        parameter: paramName,
        method: endpoint.method,
        payload,
        evidence: result.evidence,
        confidence: 'High', // Mapping 0.85+ to High since it's an enum
        severity: getSeverityForType(vulnType), // helper
        recommendation: getRecommendation(vulnType),
      };
    }
    return null;
  });

  const allResults = await Promise.all(promises);
  const confirmed = allResults.filter(r => r !== null);
  
  if (confirmed.length > 0) {
    return [confirmed[0]]; // One confirmed finding per parameter per type is enough
  }
  return [];
}

/**
 * Scan a single endpoint for multiple vulnerability types
 */
async function scanEndpoint(endpoint) {
  const allFindings = [];

  // 1. Security headers check (always, on every endpoint)
  const headerFindings = await checkSecurityHeaders(endpoint);
  allFindings.push(...headerFindings);

  // 2. Injection tests — only if there are parameters
  const paramsToTest = endpoint.params || [];

  // If no explicit params but URL has query string, extract implicitly
  try {
    const u = new URL(endpoint.url);
    u.searchParams.forEach((value, key) => {
      if (!paramsToTest.find((p) => p.name === key)) {
        paramsToTest.push({ name: key, type: 'query' });
      }
    });
  } catch {
    // ignore
  }

  const paramPromises = paramsToTest.map(async (param) => {
    const [sql, xss, hdr, pt] = await Promise.all([
      testParameter(endpoint, param.name, 'SQL Injection'),
      testParameter(endpoint, param.name, 'XSS'),
      testParameter(endpoint, param.name, 'Header Injection'),
      testParameter(endpoint, param.name, 'Path Traversal')
    ]);
    return [...sql, ...xss, ...hdr, ...pt];
  });

  const paramResults = await Promise.all(paramPromises);
  for (const res of paramResults) {
    allFindings.push(...res);
  }

  return allFindings;
}

/**
 * Scan all discovered endpoints
 */
async function scanAll(endpoints, onProgress) {
  const allFindings = [];

  // Auth bypass: run once from the root
  if (endpoints.length > 0) {
    const authFindings = await checkAuthBypass(endpoints[0]);
    allFindings.push(...authFindings);
  }

  // Process endpoints concurrently in chunks of 5
  const CHUNK_SIZE = 5;
  for (let i = 0; i < endpoints.length; i += CHUNK_SIZE) {
    const chunk = endpoints.slice(i, i + CHUNK_SIZE);
    
    // Scan chunk concurrently
    const chunkResults = await Promise.all(
      chunk.map(async (endpoint, idx) => {
        try {
          const findings = await scanEndpoint(endpoint);
          return { findings, idx: i + idx };
        } catch (err) {
          console.warn(`[Scanner] Error scanning ${endpoint.url}: ${err.message}`);
          return { findings: [], idx: i + idx };
        }
      })
    );

    for (const result of chunkResults) {
      allFindings.push(...result.findings);
      if (onProgress) {
        onProgress(result.idx + 1, endpoints.length);
      }
    }
  }

  return allFindings;
}

function getRecommendation(type) {
  const recs = {
    'SQL Injection':
      'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Implement an ORM with safe query building.',
    XSS: 'Encode all user-supplied data before rendering. Implement a strict Content-Security-Policy. Use a framework that auto-escapes template output.',
    'Header Injection':
      'Validate and sanitize all user input before using it in HTTP headers. Strip CR (\\r) and LF (\\n) characters from header values.',
    'Path Traversal':
      'Use allowlists for file paths. Resolve canonical paths server-side and ensure they stay within the intended directory.',
    'Missing Security Header':
      'Configure your web server or application to send the missing security header on all responses.',
    'Auth Bypass':
      'Implement server-side session validation on every protected route. Use middleware-level authentication guards.',
  };
  return recs[type] || 'Consult OWASP guidelines for remediation of this vulnerability type.';
}

function getSeverityForType(type) {
  if (type === 'SQL Injection' || type === 'Path Traversal' || type === 'Auth Bypass') return 'high';
  if (type === 'XSS' || type === 'Header Injection') return 'medium';
  return 'low';
}

module.exports = { scanAll, scanEndpoint, checkSecurityHeaders, checkAuthBypass };
