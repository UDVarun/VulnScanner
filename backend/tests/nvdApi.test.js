const { lookupCVE, FALLBACK_CVE } = require('../engines/nvdApi');

jest.mock('axios', () => ({
  get: jest.fn(() => Promise.reject(new Error('Network error'))),
}));

describe('NVD API Engine', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('falls back to local CVE table on API failure for SQL Injection', async () => {
    const result = await lookupCVE('SQL Injection');
    expect(result).toBeDefined();
    expect(result.cveId).toBe(FALLBACK_CVE['SQL Injection'].cveId);
    expect(result.cvssScore).toBe(FALLBACK_CVE['SQL Injection'].cvssScore);
    expect(result.severity).toBe('Critical');
  });

  test('falls back to local CVE table for XSS', async () => {
    const result = await lookupCVE('XSS');
    expect(result).toBeDefined();
    expect(result.cveId).toBe(FALLBACK_CVE['XSS'].cveId);
    expect(result.cvssScore).toBe(FALLBACK_CVE['XSS'].cvssScore);
    expect(result.severity).toBe('Medium');
  });

  test('returns default object for unknown vulnerability type', async () => {
    const result = await lookupCVE('Unknown Alien Attack');
    expect(result.cveId).toBe('N/A');
    expect(result.cvssScore).toBe(5.0);
    expect(result.severity).toBe('Medium');
  });
});
