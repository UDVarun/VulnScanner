const { analyze } = require('../engines/analyzerEngine');

describe('Analyzer Engine', () => {
  describe('SQL Injection', () => {
    test('detects SQL error string in response body', () => {
      const baseline = { status: 200, body: 'Welcome to the page' };
      const injected = { status: 500, body: 'Error: You have an error in your SQL syntax near ...' };

      const result = analyze('SQL Injection', "' OR 1=1 --", baseline, injected);
      expect(result.vulnerable).toBe(true);
      expect(result.evidence).toContain('SQL error detected');
    });

    test('ignores normal error responses', () => {
      const baseline = { status: 200, body: 'Welcome' };
      const injected = { status: 500, body: 'Internal Server Error: Connection Timeout' };

      const result = analyze('SQL Injection', "'", baseline, injected);
      expect(result.vulnerable).toBe(false);
    });

    test('detects time-based SQLi (SLEEP)', () => {
      const baseline = { status: 200, responseTime: 100 };
      const injected = { status: 200, responseTime: 2500 };

      const result = analyze('SQL Injection', "1' AND SLEEP(2) --", baseline, injected);
      expect(result.vulnerable).toBe(true);
      expect(result.evidence).toContain('Time-based SQLi');
    });
  });

  describe('XSS', () => {
    test('detects reflected payload in body', () => {
      const baseline = { status: 200, body: 'Hello guest' };
      const injected = { status: 200, body: 'Hello <script>alert(1)</script>' };

      const result = analyze('XSS', '<script>alert(1)</script>', baseline, injected);
      expect(result.vulnerable).toBe(true);
      expect(result.confidence).toBe('High');
    });
  });

  describe('Path Traversal', () => {
    test('detects /etc/passwd contents', () => {
      const baseline = { status: 200, body: 'Profile image here' };
      const injected = { status: 200, body: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' };

      const result = analyze('Path Traversal', '../../../../etc/passwd', baseline, injected);
      expect(result.vulnerable).toBe(true);
    });
  });
});
