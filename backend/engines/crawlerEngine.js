const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1'
};

const MAX_URLS   = 50;
const MAX_DEPTH  = 3;
const REQ_TIMEOUT = 15000;

/**
 * Crawl a target URL using BFS.
 * Returns array of endpoint objects.
 */
async function crawl(targetUrl) {
  console.log(`[crawler] Starting crawl: ${targetUrl}`);

  let origin;
  try {
    origin = new URL(targetUrl).origin;
  } catch (e) {
    console.error(`[crawler] Invalid URL: ${targetUrl}`);
    return [];
  }

  const visited   = new Set();
  const queue     = [{ url: targetUrl, depth: 0 }];
  const endpoints = [];

  while (queue.length > 0 && endpoints.length < MAX_URLS) {
    const { url, depth } = queue.shift();

    // normalise URL — strip fragment
    let normUrl;
    try {
      const u = new URL(url);
      u.hash = '';
      normUrl = u.toString();
    } catch {
      continue;
    }

    if (visited.has(normUrl)) continue;
    if (depth > MAX_DEPTH)    continue;
    visited.add(normUrl);

    // skip non-http schemes
    if (!normUrl.startsWith('http://') && !normUrl.startsWith('https://')) continue;

    // skip obviously binary extensions
    if (/\.(jpg|jpeg|png|gif|svg|ico|webp|pdf|zip|gz|tar|mp4|mp3|woff|woff2|ttf|eot)(\?|$)/i.test(normUrl)) {
      continue;
    }

    let response;
    try {
      console.log(`[crawler] Fetching: ${normUrl}`);
      response = await axios.get(normUrl, {
        headers:        BROWSER_HEADERS,
        timeout:        REQ_TIMEOUT,
        maxRedirects:   5,
        validateStatus: () => true   // never throw on any HTTP status
      });
    } catch (err) {
      console.warn(`[crawler] Request failed for ${normUrl}: ${err.message}`);
      // still record this URL as a failed endpoint
      endpoints.push({
        url:      normUrl,
        method:   'GET',
        forms:    0,
        params:   new URL(normUrl).searchParams.size,
        status:   0,
        testedAt: new Date()
      });
      continue;
    }

    const status      = response.status;
    const contentType = (response.headers['content-type'] || '').toLowerCase();
    const body        = typeof response.data === 'string'
                          ? response.data
                          : JSON.stringify(response.data || '');

    // count query params
    const paramCount = new URL(normUrl).searchParams.size;

    // parse HTML — even if content-type is wrong, try if body looks like HTML
    const looksLikeHtml = body.includes('<') && (
      body.includes('<html') ||
      body.includes('<body') ||
      body.includes('<a ')   ||
      body.includes('<form') ||
      body.includes('<div')  ||
      contentType.includes('text/html')
    );

    let formCount = 0;

    if (looksLikeHtml) {
      try {
        const $ = cheerio.load(body);

        // count forms
        formCount = $('form').length;

        // extract all links
        $('a[href]').each((_, el) => {
          const href = $(el).attr('href');
          if (!href) return;

          let resolved;
          try {
            resolved = new URL(href, normUrl).toString();
          } catch {
            return;
          }

          // same-origin only
          try {
            if (new URL(resolved).origin !== origin) return;
          } catch {
            return;
          }

          // strip fragment
          try {
            const u = new URL(resolved);
            u.hash  = '';
            resolved = u.toString();
          } catch {
            return;
          }

          if (!visited.has(resolved) && endpoints.length + queue.length < MAX_URLS * 2) {
            queue.push({ url: resolved, depth: depth + 1 });
          }
        });

        // extract form action URLs
        $('form').each((_, el) => {
          const action = $(el).attr('action');
          const method = ($(el).attr('method') || 'GET').toUpperCase();
          if (!action) return;

          let resolved;
          try {
            resolved = new URL(action, normUrl).toString();
          } catch {
            return;
          }

          try {
            if (new URL(resolved).origin !== origin) return;
          } catch {
            return;
          }

          // add form POST endpoints
          if (method === 'POST') {
            const inputs = [];
            $(el).find('input, select, textarea').each((_, inp) => {
              const name = $(inp).attr('name');
              if (name) inputs.push(name);
            });
            endpoints.push({
              url:      resolved,
              method:   'POST',
              forms:    1,
              params:   inputs.length,
              status:   0,       // not fetched yet
              testedAt: new Date(),
              inputs:   inputs
            });
          } else {
            // GET form — add to queue
            if (!visited.has(resolved)) {
              queue.push({ url: resolved, depth: depth + 1 });
            }
          }
        });

      } catch (parseErr) {
        console.warn(`[crawler] Cheerio parse error on ${normUrl}: ${parseErr.message}`);
      }
    }

    // record this endpoint
    endpoints.push({
      url:      normUrl,
      method:   'GET',
      forms:    formCount,
      params:   paramCount,
      status:   status,
      testedAt: new Date()
    });

    console.log(`[crawler] Recorded endpoint: ${normUrl} (status=${status}, forms=${formCount}, queue=${queue.length})`);
  }

  // deduplicate by url
  const seen = new Set();
  const unique = endpoints.filter(ep => {
    if (seen.has(ep.url)) return false;
    seen.add(ep.url);
    return true;
  });

  console.log(`[crawler] Crawl complete. Found ${unique.length} endpoints.`);
  return unique;
}

module.exports = { crawl };
