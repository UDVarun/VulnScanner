/**
 * Crawler Engine
 * BFS-based web crawler. Discovers endpoints, forms, and query params.
 */
const axios = require('axios');
const cheerio = require('cheerio');

const REQUEST_TIMEOUT = 15000; // 15 seconds
const MAX_DEPTH = 3;
const MAX_URLS = 50;

// Browser-like User-Agent to avoid bot-blocking
const DEFAULT_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1',
};

/**
 * Normalize a URL — resolve relative against base, strip fragments
 */
function normalizeUrl(rawUrl, base) {
  try {
    const resolved = new URL(rawUrl, base);
    resolved.hash = '';
    return resolved.href;
  } catch {
    return null;
  }
}

/**
 * Check if a URL belongs to the same origin as the target
 */
function isSameOrigin(url, targetOrigin) {
  try {
    return new URL(url).origin === targetOrigin;
  } catch {
    return false;
  }
}

/**
 * Returns true if this content type is truly non-crawlable binary content.
 * Note: we do NOT skip text/html=false here — we also check the body for HTML.
 */
function isBinaryContent(contentType) {
  if (!contentType) return false;
  return (
    contentType.includes('application/pdf') ||
    contentType.includes('application/zip') ||
    contentType.includes('application/octet-stream') ||
    contentType.includes('application/exe') ||
    (contentType.includes('image/') && !contentType.includes('image/svg'))
  );
}

/**
 * Extract all links and forms from an HTML page
 */
function extractEndpoints(html, pageUrl) {
  const $ = cheerio.load(html);
  const links = new Set();
  const forms = [];

  // Extract <a href> links
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href && !href.startsWith('mailto:') && !href.startsWith('tel:') && !href.startsWith('javascript:')) {
      const normalized = normalizeUrl(href, pageUrl);
      if (normalized) links.add(normalized);
    }
  });

  // Extract <form> definitions
  $('form').each((_, el) => {
    const form = $(el);
    const action = form.attr('action') || pageUrl;
    const method = (form.attr('method') || 'GET').toUpperCase();
    const resolvedAction = normalizeUrl(action, pageUrl);

    const inputs = [];
    form.find('input, textarea, select').each((__, inputEl) => {
      const name = $(inputEl).attr('name');
      const type = $(inputEl).attr('type') || 'text';
      if (name) {
        inputs.push({ name, type });
      }
    });

    if (resolvedAction && inputs.length > 0) {
      forms.push({ url: resolvedAction, method, params: inputs });
      links.add(resolvedAction);
    }
  });

  return { links: Array.from(links), formsCount: forms.length, forms };
}

/**
 * Main crawl function
 * @param {string} targetUrl - Root URL to start crawling
 * @param {number} maxDepth - Max BFS depth
 * @returns {Promise<Array>} - Array of endpoint objects
 */
async function crawl(targetUrl, maxDepth = MAX_DEPTH) {
  const targetOrigin = new URL(targetUrl).origin;
  const visited = new Set();
  const queue = [{ url: targetUrl, depth: 0 }];
  const endpoints = [];

  // Always include the root
  visited.add(targetUrl);

  while (queue.length > 0 && endpoints.length < MAX_URLS) {
    const { url, depth } = queue.shift();

    try {
      console.log(`[Crawler] Fetching (depth=${depth}): ${url}`);
      const response = await axios.get(url, {
        headers: DEFAULT_HEADERS,
        timeout: REQUEST_TIMEOUT,
        maxRedirects: 5,
        validateStatus: () => true, // Accept all status codes
      });

      const contentType = response.headers['content-type'] || '';

      // Skip truly binary content (images, PDFs, ZIPs, etc.) but NOT wrong-typed HTML
      if (isBinaryContent(contentType)) {
        console.log(`[Crawler] Skipping binary content at ${url} (${contentType})`);
        // Still record the URL as an endpoint
        const parsedUrl = new URL(url);
        const searchParams = parsedUrl.searchParams;
        const paramsCount = searchParams.size || searchParams.toString().split('&').filter(Boolean).length;
        endpoints.push({
          url,
          method: 'GET',
          params: paramsCount,
          forms: 0,
          status: response.status,
          testedAt: new Date(),
          rawParams: [],
          rawForms: [],
        });
        continue;
      }

      // Check if the body looks like HTML (even if Content-Type says otherwise)
      const body = typeof response.data === 'string' ? response.data : '';
      const looksLikeHtml = (
        body.includes('<html') ||
        body.includes('<body') ||
        body.includes('<a ') ||
        body.includes('<form') ||
        contentType.includes('text/html')
      );

      // Add current page as endpoint with query params
      const parsedUrl = new URL(url);
      const searchParams = parsedUrl.searchParams;
      const paramsCount = searchParams.size || searchParams.toString().split('&').filter(Boolean).length;
      const params = [];
      searchParams.forEach((value, key) => {
        params.push({ name: key, type: 'query' });
      });

      // Parse HTML if the body looks like HTML regardless of Content-Type
      let formsCount = 0;
      let links = [];
      let forms = [];

      if (looksLikeHtml) {
        const extracted = extractEndpoints(body, url);
        links = extracted.links;
        forms = extracted.forms;
        formsCount = extracted.formsCount;
      }

      endpoints.push({
        url,
        method: 'GET',
        params: paramsCount,
        forms: formsCount,
        status: response.status,
        testedAt: new Date(),
        rawParams: params,
        rawForms: forms.filter((f) => f.url === url),
      });

      // BFS: enqueue new links
      if (depth < maxDepth && looksLikeHtml) {
        for (const link of links) {
          if (!visited.has(link) && isSameOrigin(link, targetOrigin)) {
            visited.add(link);
            queue.push({ url: link, depth: depth + 1 });
          }
        }

        // Enqueue form action URLs and record them as endpoints
        for (const form of forms) {
          if (!endpoints.find((e) => e.url === form.url && e.method === form.method)) {
            endpoints.push({
              url: form.url,
              method: form.method,
              params: form.params.length,
              forms: 1, // It's a form action, so it counts as 1 form found
              status: 0, // Not visited as a main page yet
              testedAt: new Date(),
              rawParams: form.params.map((p) => ({ name: p.name, type: 'form' })),
              rawForms: [form],
            });
          }

          if (!visited.has(form.url) && isSameOrigin(form.url, targetOrigin)) {
            visited.add(form.url);
            queue.push({ url: form.url, depth: depth + 1 });
          }
        }
      }
    } catch (err) {
      console.warn(`[Crawler] Failed to fetch ${url}: ${err.message}`);
      // Still add this URL to endpoints so scanner can test it
      try {
        const parsedUrl = new URL(url);
        const paramsCount = parsedUrl.searchParams.size || 0;
        endpoints.push({
          url,
          method: 'GET',
          params: paramsCount,
          forms: 0,
          status: err.response?.status || 0,
          testedAt: new Date(),
          rawParams: [],
          rawForms: [],
        });
      } catch {
        // ignore URL parse errors
      }
    }
  }

  // Deduplicate endpoints by URL+method
  const seen = new Set();
  return endpoints.filter((ep) => {
    const key = `${ep.method}:${ep.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { crawl };
