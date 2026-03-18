/**
 * Analyzer Engine
 * Compares baseline vs injected responses to detect real vulnerabilities.
 * Reduces false positives by requiring multiple signals.
 */

// SQL error patterns that indicate real SQL injection
const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /MySQLSyntaxErrorException/i,
  /valid MySQL result/i,
  /check the manual that corresponds to your MySQL/i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /PG::SyntaxError/i,
  /org\.postgresql\.util\.PSQLException/i,
  /ERROR:\s+syntax error at or near/i,
  /ORA-\d{4,5}/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /Unclosed quotation mark after the character string/i,
  /mssql_query\(\)/i,
  /ODBC Driver.*SQL Server/i,
  /SQLite.*Error/i,
  /syntax error/i,
  /mysql_fetch_array\(\)/i,
  /mysql_fetch_assoc\(\)/i,
  /mysql_num_rows\(\)/i,
  /DB2 SQL error/i,
  /You have an error in your SQL syntax/i,
  /supplied argument is not a valid MySQL/i,
  /Column count doesn't match/i,
  /UNION.*SELECT/i,
];

// XSS detection: payload reflection
function detectXSSReflection(payload, responseBody) {
  if (!responseBody) return false;
  // Check multiple forms of the payload to handle partial encoding
  const variants = [
    payload,
    payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'),
    encodeURIComponent(payload),
  ];
  return variants.some((v) => responseBody.includes(v));
}

// SQL injection detection
function detectSQLi(payload, baseline, injected) {
  const evidence = [];
  let score = 0;

  // 1. Error pattern match in response body
  const body = (injected.body || '').substring(0, 50000);
  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = body.match(pattern);
    if (match) {
      evidence.push(`SQL error detected: "${match[0].trim()}"`);
      score += 3;
      break;
    }
  }

  // 2. Status code change (200 → 500 suggests DB error)
  if (baseline.status === 200 && injected.status === 500) {
    evidence.push(`Status changed: ${baseline.status} → ${injected.status}`);
    score += 2;
  }

  // 3. Significant response body length change
  const baseLength = (baseline.body || '').length;
  const injLength = (injected.body || '').length;
  const diffPercent = baseLength > 0 ? Math.abs(injLength - baseLength) / baseLength : 0;
  if (diffPercent > 0.2 && Math.abs(injLength - baseLength) > 100) {
    evidence.push(`Response length changed by ${Math.round(diffPercent * 100)}% (${baseLength} → ${injLength} bytes)`);
    score += 1;
  }

  // 4. Time-based detection for SLEEP payloads
  if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
    if (injected.responseTime > 1800) {
      // > 1.8 seconds delay
      evidence.push(`Time-based SQLi: response took ${injected.responseTime}ms`);
      score += 3;
    }
  }

  return {
    vulnerable: score >= 3,
    evidence: evidence.join('; '),
    confidence: score >= 4 ? 'High' : score >= 3 ? 'Medium' : 'Low',
  };
}

/**
 * Main analysis function
 * @param {string} type - Vulnerability type
 * @param {string} payload - The payload used
 * @param {Object} baseline - { status, body, responseTime, headers }
 * @param {Object} injected - { status, body, responseTime, headers }
 * @returns {{ vulnerable: boolean, evidence: string, confidence: string }}
 */
function analyze(type, payload, baseline, injected) {
  if (!baseline || !injected) {
    return { vulnerable: false, evidence: 'No response data', confidence: 'Low' };
  }

  switch (type) {
    case 'SQL Injection': {
      return detectSQLi(payload, baseline, injected);
    }

    case 'XSS': {
      const reflected = detectXSSReflection(payload, injected.body);
      return {
        vulnerable: reflected,
        evidence: reflected
          ? `Payload reflected in response: ...${(injected.body || '').substring(
              Math.max(0, (injected.body || '').indexOf(payload) - 50),
              (injected.body || '').indexOf(payload) + payload.length + 50
            )}...`
          : 'Payload not reflected',
        confidence: reflected ? 'High' : 'Low',
      };
    }

    case 'Header Injection': {
      // Check if CRLF was processed (header appears in response)
      const responseHeaders = JSON.stringify(injected.headers || {});
      const injected_val = responseHeaders.includes('Injected') || responseHeaders.includes('injected');
      return {
        vulnerable: injected_val,
        evidence: injected_val ? 'CRLF injection reflected in response headers' : 'No header injection detected',
        confidence: injected_val ? 'High' : 'Low',
      };
    }

    case 'Path Traversal': {
      const body = (injected.body || '').substring(0, 10000);
      const etcPasswd = /root:.*:0:0:|daemon:|bin:|sys:/i.test(body);
      const winHosts = /# Copyright.*Microsoft|127\.0\.0\.1.*localhost/i.test(body);
      const vulnerable = etcPasswd || winHosts;
      return {
        vulnerable,
        evidence: vulnerable ? 'System file content detected in response' : 'No path traversal detected',
        confidence: vulnerable ? 'High' : 'Low',
      };
    }

    default:
      return { vulnerable: false, evidence: 'Unknown type', confidence: 'Low' };
  }
}

module.exports = { analyze, SQL_ERROR_PATTERNS };
