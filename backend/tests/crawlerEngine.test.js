const { crawl } = require('../engines/crawlerEngine');
const axios = require('axios');

jest.mock('axios');

describe('Crawler Engine', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('extracts links and forms from html', async () => {
    const html = `
      <html>
        <body>
          <a href="/about">About</a>
          <a href="http://external.com">External</a>
          <form action="/login" method="POST">
            <input name="username" type="text" />
            <input name="password" type="password" />
          </form>
        </body>
      </html>
    `;

    axios.get.mockResolvedValue({
      status: 200,
      headers: { 'content-type': 'text/html' },
      data: html,
    });

    const endpoints = await crawl('http://test.com', 1);

    // Should include root url with GET
    expect(endpoints).toContainEqual(
      expect.objectContaining({ url: 'http://test.com', method: 'GET' })
    );

    // Should include /about link
    expect(endpoints).toContainEqual(
      expect.objectContaining({ url: 'http://test.com/about', method: 'GET' })
    );

    // Should include /login form
    expect(endpoints).toContainEqual(
      expect.objectContaining({
        url: 'http://test.com/login',
        method: 'POST',
        params: [
          { name: 'username', type: 'form' },
          { name: 'password', type: 'form' },
        ],
      })
    );

    // Should NOT include external links
    const external = endpoints.find((e) => e.url === 'http://external.com/');
    expect(external).toBeUndefined();
  });

  test('extracts query params from root URL', async () => {
    axios.get.mockResolvedValue({
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      data: '<html><body>No links here</body></html>',
    });

    const endpoints = await crawl('http://test.com/?search=hello&page=1', 1);

    const rootEndpoint = endpoints.find(e => e.url === 'http://test.com/?search=hello&page=1');
    expect(rootEndpoint).toBeDefined();
    expect(rootEndpoint.params).toContainEqual({ name: 'search', type: 'query' });
    expect(rootEndpoint.params).toContainEqual({ name: 'page', type: 'query' });
  });

  test('respects max depth and handles non-html gracefully', async () => {
    // Return image content
    axios.get.mockResolvedValue({
      status: 200,
      headers: { 'content-type': 'image/png' },
      data: 'binarydata',
    });

    const endpoints = await crawl('http://test.com/logo.png', 1);
    
    // Non-html shouldn't add endpoints beyond the root attempt which skips processing
    expect(endpoints.length).toBe(0);
  });
});
