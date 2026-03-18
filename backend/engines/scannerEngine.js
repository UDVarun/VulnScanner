/**
 * Scanner Engine
 * Core scanning logic: sends baseline + injected requests and detects vulnerabilities.
 * Handles SQLi, XSS, Security Headers, Auth Bypass, Path Traversal, Header Injection.
 */
const axios = require('axios');
const { getPayloads } = require('./payloadEngine');
const { analyze } = require('./analyzerEngine');

const REQUEST_TIMEOUT = 12000;
const DELAY_BETWEEN_REQUESTS = 300; // ms — be respectful to target

const DEFAULT_HEADERS = {
  'User-Agent': 'VulnScanner/1.0 (Security Research Tool)',
  Accept: 'text/html,application/xhtml+xml,*/*;q=0.9',
  'Accept-Language': 'en-US,en;q=0.5',
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

  if (response.error) return findings;

  for (const headerDef of REQUIRED_SECURITY_HEADERS) {
    const headerVal = response.headers[headerDef.name];
    if (!headerVal) {
      findings.push({
        type: 'Missing Security Header',
        severity: 'Medium',
        endpoint: endpoint.url,
        parameter: headerDef.description,
        payload: 'N/A',
        evidence: `Missing HTTP security header: ${headerDef.description}`,
        confidence: 'High',
        recommendation: headerDef.recommendation,
      });
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
        findings.push({
          type: 'Auth Bypass',
          severity: 'High',
          endpoint: targetUrl,
          parameter: 'Path Access',
          payload: path,
          evidence: `Protected path accessible without authentication (HTTP ${response.status}, ${response.body.length} bytes)`,
          confidence: 'Medium',
          recommendation:
            'Implement proper authentication and authorization checks on all administrative endpoints.',
        });
        // Only report once per base origin
        break;
      }
    } catch {
      // Ignore errors on auth bypass checks
    }
  }

  return findings;
}

/**
 * Test a single parameter for injection vulnerabilities
 */
async function testParameter(endpoint, paramName, vulnType) {
  const findings = [];
  const payloads = getPayloads(vulnType);

  // Baseline request
  const baseline = await makeRequest(endpoint.url, { method: endpoint.method });
  await sleep(DELAY_BETWEEN_REQUESTS);

  for (const payloadObj of payloads) {
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
    await sleep(DELAY_BETWEEN_REQUESTS);

    const result = analyze(vulnType, payload, baseline, injected);

    if (result.vulnerable && result.confidence !== 'Low') {
      findings.push({
        type: vulnType,
        endpoint: endpoint.url,
        parameter: paramName,
        method: endpoint.method,
        payload,
        evidence: result.evidence,
        confidence: result.confidence,
        recommendation: getRecommendation(vulnType),
      });
      // One confirmed finding per parameter per type is enough
      break;
    }
  }

  return findings;
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

  for (const param of paramsToTest) {
    // SQL Injection
    const sqlFindings = await testParameter(endpoint, param.name, 'SQL Injection');
    allFindings.push(...sqlFindings);

    // XSS
    const xssFindings = await testParameter(endpoint, param.name, 'XSS');
    allFindings.push(...xssFindings);

    // Header Injection
    const hdrFindings = await testParameter(endpoint, param.name, 'Header Injection');
    allFindings.push(...hdrFindings);

    // Path Traversal
    const ptFindings = await testParameter(endpoint, param.name, 'Path Traversal');
    allFindings.push(...ptFindings);
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

  for (let i = 0; i < endpoints.length; i++) {
    const endpoint = endpoints[i];
    try {
      const findings = await scanEndpoint(endpoint);
      allFindings.push(...findings);
    } catch (err) {
      console.warn(`[Scanner] Error scanning ${endpoint.url}: ${err.message}`);
    }

    if (onProgress) {
      onProgress(i + 1, endpoints.length);
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

module.exports = { scanAll, scanEndpoint, checkSecurityHeaders, checkAuthBypass };
