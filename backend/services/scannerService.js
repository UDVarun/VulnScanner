/**
 * Scanner Service — Orchestrator
 * Coordinates the full scan workflow:
 * crawl → scan → NVD lookup → persist → emit progress
 */
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const { crawl } = require('../engines/crawlerEngine');
const { scanAll } = require('../engines/scannerEngine');
const { lookupCVE, cvssToSeverity } = require('../engines/nvdApi');

/**
 * Emit real-time progress via Socket.IO to the scan's room
 */
function emitProgress(io, scanId, data) {
  if (io) {
    io.to(scanId).emit('scan_progress', { scanId, ...data });
  }
}

/**
 * Main entry point for a scan
 * @param {string} scanId - MongoDB ObjectId string
 * @param {string} targetUrl - URL to scan
 * @param {object} io - Socket.IO server instance
 */
async function startScan(scanId, targetUrl, io) {
  console.log(`[ScanService] Starting scan ${scanId} for ${targetUrl}`);

  try {
    // ── PHASE 1: Mark as running ──────────────────────────
    await Scan.findByIdAndUpdate(scanId, {
      status: 'running',
      progress: 5,
      currentActivity: 'Crawling target for endpoints...',
    });

    emitProgress(io, scanId, {
      progress: 5,
      status: 'running',
      activity: 'Crawling target for endpoints...',
    });

    // ── PHASE 2: Crawl ────────────────────────────────────
    let endpoints = [];
    try {
      endpoints = await crawl(targetUrl, 2);
      console.log(`[ScanService] Crawled ${endpoints.length} endpoints`);
    } catch (err) {
      console.error(`[ScanService] Crawl error: ${err.message}`);
      // If crawl fails entirely, create a minimal endpoint for the root URL
      endpoints = [{ url: targetUrl, method: 'GET', params: [], forms: [] }];
    }

    await Scan.findByIdAndUpdate(scanId, {
      totalEndpoints: endpoints.length,
      progress: 20,
      currentActivity: `Discovered ${endpoints.length} endpoints. Starting vulnerability scan...`,
    });

    emitProgress(io, scanId, {
      progress: 20,
      activity: `Discovered ${endpoints.length} endpoints. Starting vulnerability scan...`,
      totalEndpoints: endpoints.length,
    });

    // ── PHASE 3: Scan all endpoints ───────────────────────
    const rawFindings = [];

    const onProgress = async (scanned, total) => {
      const pct = 20 + Math.floor((scanned / total) * 55); // 20%→75%
      await Scan.findByIdAndUpdate(scanId, {
        scannedEndpoints: scanned,
        progress: pct,
        currentActivity: `Scanning endpoint ${scanned} of ${total}...`,
      });
      emitProgress(io, scanId, {
        progress: pct,
        activity: `Scanning endpoint ${scanned} of ${total}...`,
        scannedEndpoints: scanned,
      });
    };

    const findings = await scanAll(endpoints, onProgress);
    rawFindings.push(...findings);

    console.log(`[ScanService] Found ${rawFindings.length} raw vulnerabilities`);

    // ── PHASE 4: NVD CVE lookup ───────────────────────────
    await Scan.findByIdAndUpdate(scanId, {
      progress: 78,
      currentActivity: 'Looking up CVE data from NVD...',
    });
    emitProgress(io, scanId, { progress: 78, activity: 'Looking up CVE data from NVD...' });

    const savedVulns = [];
    const typesSeen = new Set();
    const cveCache = {};

    for (const finding of rawFindings) {
      if (finding.suppress) continue;
      
      const isInfo = (finding.severity && finding.severity.toLowerCase() === 'info');

      // Fetch CVE once per type (skip for info)
      if (!isInfo && !cveCache[finding.type]) {
        try {
          cveCache[finding.type] = await lookupCVE(finding.type);
        } catch {
          cveCache[finding.type] = { cveId: 'N/A', cvssScore: 0, severity: 'Low', description: '' };
        }
      } else if (isInfo && !cveCache[finding.type]) {
        cveCache[finding.type] = { cveId: 'N/A', cvssScore: 0, severity: 'info', description: '' };
      }

      const cveData = cveCache[finding.type];
      const severity = finding.severity || cvssToSeverity(cveData.cvssScore);

      // Do not persist suppressed or info findings
      if (finding.suppress || severity.toLowerCase() === 'info') {
        // Still push it to savedVulns so it's counted in summary.info
        savedVulns.push({ severity, ...finding });
        continue;
      }

      const vuln = new Vulnerability({
        scanId,
        type: finding.type,
        severity,
        cveId: cveData.cveId,
        cvssScore: cveData.cvssScore,
        cvssVector: cveData.cvssVector || 'N/A',
        cveDescription: cveData.description || '',
        endpoint: finding.endpoint,
        parameter: finding.parameter || '',
        method: finding.method || 'GET',
        payload: finding.payload || '',
        evidence: finding.evidence || '',
        confidence: finding.confidence || 'Medium',
        recommendation: finding.recommendation || '',
      });

      await vuln.save();
      savedVulns.push(vuln);

      emitProgress(io, scanId, {
        newVulnerability: {
          type: finding.type,
          severity,
          endpoint: finding.endpoint,
          cveId: cveData.cveId,
          cvssScore: cveData.cvssScore,
        },
      });
    }

    // ── PHASE 5: Build summary and complete ───────────────
    // savedVulns contains both saved Mongoose docs AND plain objects for informational ones
    const realFindings = savedVulns.filter((v) => v.severity.toLowerCase() !== 'info');
    const summary = {
      critical: realFindings.filter((v) => v.severity.toLowerCase() === 'critical').length,
      high: realFindings.filter((v) => v.severity.toLowerCase() === 'high').length,
      medium: realFindings.filter((v) => v.severity.toLowerCase() === 'medium').length,
      low: realFindings.filter((v) => v.severity.toLowerCase() === 'low').length,
      info: savedVulns.filter((v) => v.severity.toLowerCase() === 'info').length,
      total: realFindings.length, // total only includes real findings, not info
    };

    await Scan.findByIdAndUpdate(scanId, {
      status: 'completed',
      progress: 100,
      currentActivity: 'Scan complete.',
      summary,
      completedAt: new Date(),
    });

    emitProgress(io, scanId, {
      progress: 100,
      status: 'completed',
      activity: 'Scan complete.',
      summary,
    });

    console.log(`[ScanService] Scan ${scanId} completed. Found ${savedVulns.length} vulnerabilities.`);
  } catch (err) {
    console.error(`[ScanService] Fatal error in scan ${scanId}:`, err.message);
    await Scan.findByIdAndUpdate(scanId, {
      status: 'failed',
      error: err.message,
      progress: 0,
      currentActivity: 'Scan failed.',
    });
    emitProgress(io, scanId, {
      status: 'failed',
      activity: `Scan failed: ${err.message}`,
    });
  }
}

module.exports = { startScan };
