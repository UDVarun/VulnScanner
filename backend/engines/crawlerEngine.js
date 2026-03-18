/**
 * Crawler Engine
 * BFS-based web crawler. Discovers endpoints, forms, and query params.
 */
const axios = require('axios');
const cheerio = require('cheerio');

const REQUEST_TIMEOUT = 10000; // 10 seconds
const MAX_DEPTH = 2;
const MAX_URLS = 30;

const DEFAULT_HEADERS = {
  'User-Agent': 'VulnScanner/1.0 (Security Research Tool)',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
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

  return { links: Array.from(links), forms };
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
      if (!contentType.includes('text/html')) {
        continue;
      }

      const { links, forms } = extractEndpoints(response.data, url);

      // Add current page as endpoint with query params
      const parsedUrl = new URL(url);
      const params = [];
      parsedUrl.searchParams.forEach((value, key) => {
        params.push({ name: key, type: 'query' });
      });

      endpoints.push({
        url,
        method: 'GET',
        params,
        forms: forms.filter((f) => f.url === url),
      });

      // BFS: enqueue new links
      if (depth < maxDepth) {
        for (const link of links) {
          if (!visited.has(link) && isSameOrigin(link, targetOrigin)) {
            visited.add(link);
            queue.push({ url: link, depth: depth + 1 });
          }
        }

        // Enqueue form action URLs
        for (const form of forms) {
          endpoints.push({
            url: form.url,
            method: form.method,
            params: form.params.map((p) => ({ name: p.name, type: 'form' })),
            forms: [form],
          });

          if (!visited.has(form.url) && isSameOrigin(form.url, targetOrigin)) {
            visited.add(form.url);
          }
        }
      }
    } catch (err) {
      console.warn(`[Crawler] Failed to fetch ${url}: ${err.message}`);
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
