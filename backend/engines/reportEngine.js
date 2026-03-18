/**
 * PDF Report Engine
 * Generates professional security audit reports using PDFKit.
 */
const PDFDocument = require('pdfkit');

// Color palette
const COLORS = {
  bg: '#0d1117',
  primary: '#00d4ff',
  danger: '#ff4444',
  warning: '#ffaa00',
  success: '#00cc66',
  info: '#6688cc',
  textPrimary: '#e6edf3',
  textSecondary: '#8b949e',
  border: '#30363d',
  critical: '#ff0000',
  high: '#ff4444',
  medium: '#ffaa00',
  low: '#00cc66',
};

function severityColor(severity) {
  switch (severity) {
    case 'Critical': return COLORS.critical;
    case 'High': return COLORS.high;
    case 'Medium': return COLORS.medium;
    case 'Low': return COLORS.low;
    default: return COLORS.info;
  }
}

function addEndpointsSection(doc, scan) {
  const endpoints = scan.endpoints || [];

  doc.addPage();
  doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');
  
  doc.fill('#00d4ff').fontSize(18).font('Helvetica-Bold').text('Endpoints Discovered', 50, 50);
  doc.moveDown(0.5);
  doc.fontSize(11).font('Helvetica').fillColor('#8b949e')
    .text(`The crawler discovered ${endpoints.length} endpoint(s) during the scan.`);
  doc.moveDown(1);

  if (endpoints.length === 0) {
    doc.fontSize(11).font('Helvetica').fillColor('#e6edf3')
      .text('No endpoints were discovered. The target may have blocked crawling or returned no links.');
    return;
  }

  // Table header
  let ty = doc.y;
  doc.fontSize(10).font('Helvetica-Bold').fillColor('#00d4ff');
  doc.text('#', 50, ty, { width: 30 });
  doc.text('URL', 80, ty, { width: 280 });
  doc.text('Method', 360, ty, { width: 50 });
  doc.text('Status', 410, ty, { width: 40 });
  doc.text('Forms', 450, ty, { width: 40 });
  doc.text('Params', 490, ty, { width: 50 });
  doc.moveDown(0.3);

  // Divider line
  doc.moveTo(50, doc.y).lineTo(550, doc.y).strokeColor('#30363d').stroke();
  doc.moveDown(0.3);

  // Table rows
  endpoints.forEach((ep, i) => {
    if (doc.y > 750) {
      doc.addPage();
      doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');
      doc.y = 50;
    }

    const truncatedUrl = ep.url.length > 55
      ? ep.url.substring(0, 52) + '...'
      : ep.url;

    let ry = doc.y;
    doc.fontSize(9).font('Helvetica').fillColor(i % 2 === 0 ? '#e6edf3' : '#8b949e');
    doc.text(String(i + 1), 50, ry, { width: 30 });
    doc.text(truncatedUrl, 80, ry, { width: 280 });
    doc.text(ep.method || 'GET', 360, ry, { width: 50 });
    doc.text(String(ep.status || '-'), 410, ry, { width: 40 });
    doc.text(String(ep.forms || 0), 450, ry, { width: 40 });
    doc.text(String(ep.params || 0), 490, ry, { width: 50 });
    doc.moveDown(0.25);
    
    doc.moveTo(50, doc.y).lineTo(550, doc.y).strokeColor('#1c2128').lineWidth(0.5).stroke();
    doc.moveDown(0.2);
  });
}

function generatePDF(scan, vulnerabilities) {
  const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });

  // Ensure any auto-generated pages (from text wrapping) get the dark background
  doc.on('pageAdded', () => {
    doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');
  });

  // Keep only actual reportable vulnerabilities
  const reportableVulns = vulnerabilities.filter(v => (v.severity || '').toLowerCase() !== 'info');

  // ─── COVER PAGE ───────────────────────────────────────────
  doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');

  // Title banner
  doc.rect(0, 0, doc.page.width, 120).fill('#00d4ff');
  doc
    .fill('#0d1117')
    .fontSize(28)
    .font('Helvetica-Bold')
    .text('VULNSCANNER', 50, 30, { align: 'center' });
  doc
    .fontSize(14)
    .font('Helvetica')
    .text('Web Application Vulnerability Assessment Report', 50, 70, { align: 'center' });

  // Report metadata
  doc.moveDown(4);
  doc.fill('#e6edf3').fontSize(12).font('Helvetica-Bold').text('REPORT DETAILS', 50, 160);
  doc.moveTo(50, 178).lineTo(doc.page.width - 50, 178).strokeColor('#00d4ff').stroke();

  const metadata = [
    ['Target URL', scan.targetUrl],
    ['Scan ID', scan._id.toString()],
    ['Scan Date', new Date(scan.createdAt).toUTCString()],
    ['Completed', scan.completedAt ? new Date(scan.completedAt).toUTCString() : 'N/A'],
    ['Status', scan.status.toUpperCase()],
    ['Total Endpoints Scanned', String(scan.totalEndpoints || 0)],
  ];

  let y = 190;
  for (const [label, value] of metadata) {
    doc.fill('#8b949e').font('Helvetica').fontSize(10).text(label + ':', 50, y);
    doc.fill('#e6edf3').font('Helvetica').fontSize(10).text(value, 200, y);
    y += 20;
  }

  // ─── EXECUTIVE SUMMARY ────────────────────────────────────
  doc.addPage();
  doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');
  doc.rect(0, 0, doc.page.width, 60).fill('#161b22');

  doc.fill('#00d4ff').fontSize(20).font('Helvetica-Bold').text('EXECUTIVE SUMMARY', 50, 20);
  doc.fill('#8b949e').fontSize(10).font('Helvetica').text(
    'This report presents the findings of an automated web application vulnerability assessment.',
    50, 80, { width: doc.page.width - 100 }
  );

  // Summary stats boxes
  const stats = [
    { label: 'Critical', count: reportableVulns.filter((v) => v.severity === 'Critical' || v.severity === 'critical').length, color: '#ff0000' },
    { label: 'High', count: reportableVulns.filter((v) => v.severity === 'High' || v.severity === 'high').length, color: '#ff4444' },
    { label: 'Medium', count: reportableVulns.filter((v) => v.severity === 'Medium' || v.severity === 'medium').length, color: '#ffaa00' },
    { label: 'Low', count: reportableVulns.filter((v) => v.severity === 'Low' || v.severity === 'low').length, color: '#00cc66' },
    { label: 'Total', count: reportableVulns.length, color: '#00d4ff' },
  ];

  const boxW = 85;
  let bx = 50;
  for (const stat of stats) {
    doc.rect(bx, 120, boxW, 60).fill('#161b22');
    doc.rect(bx, 120, boxW, 4).fill(stat.color);
    doc.fill(stat.color).fontSize(22).font('Helvetica-Bold').text(String(stat.count), bx, 133, { width: boxW, align: 'center' });
    doc.fill('#8b949e').fontSize(9).font('Helvetica').text(stat.label, bx, 158, { width: boxW, align: 'center' });
    bx += boxW + 10;
  }

  // Risk rating
  const totalCritHigh = stats[0].count + stats[1].count;
  const riskRating = totalCritHigh > 0 ? 'HIGH RISK' : reportableVulns.length > 0 ? 'MEDIUM RISK' : 'LOW RISK';
  const riskColor = totalCritHigh > 0 ? '#ff4444' : reportableVulns.length > 0 ? '#ffaa00' : '#00cc66';

  doc.rect(50, 200, doc.page.width - 100, 40).fill('#161b22');
  doc.fill(riskColor).fontSize(14).font('Helvetica-Bold').text(`Overall Risk Rating: ${riskRating}`, 60, 213);

  const isClean = reportableVulns.length === 0;
  if (isClean) {
    doc.moveDown(2);
    doc.fontSize(13).font('Helvetica-Bold').fillColor('#22c55e') // green
      .text('No Vulnerabilities Detected', 50, 260);
    doc.moveDown(0.5);
    doc.fontSize(11).font('Helvetica').fillColor('#e6edf3')
      .text(
        `VulnScanner completed a full scan of ${scan.targetUrl} and discovered ` +
        `${scan.endpointCount || scan.totalEndpoints || 0} endpoint(s). No exploitable vulnerabilities ` +
        `were identified. The site appears to be well-configured for the tested ` +
        `vulnerability categories.`,
        50, 285, { width: doc.page.width - 100 }
      );
  }

  // ─── VULNERABILITY DETAILS ────────────────────────────────
  if (reportableVulns.length === 0) {
    // Already handled in executive summary for clean scans
  } else {
    doc.fill('#e6edf3').fontSize(14).font('Helvetica-Bold').text('VULNERABILITY FINDINGS', 50, 260);
    doc.moveTo(50, 278).lineTo(doc.page.width - 50, 278).strokeColor('#00d4ff').stroke();

    let vy = 290;
    let vulnIndex = 1;

    for (const vuln of reportableVulns) {
      // Page break if needed: require 230 points of clearance to prevent auto page-wrapping blank pages
      if (vy > doc.page.height - 230) {
        doc.addPage();
        vy = 50;
      }

      const sColor = severityColor(vuln.severity);

      // Vuln header
      doc.rect(50, vy, doc.page.width - 100, 24).fill('#161b22');
      doc.rect(50, vy, 4, 24).fill(sColor);
      doc
        .fill(sColor)
        .fontSize(10)
        .font('Helvetica-Bold')
        .text(`[${vuln.severity.toUpperCase()}]`, 60, vy + 7);
      doc
        .fill('#e6edf3')
        .fontSize(10)
        .font('Helvetica-Bold')
        .text(`${vulnIndex}. ${vuln.type}`, 120, vy + 7);
      vy += 28;

      // Details table
      const details = [
        ['Endpoint', vuln.endpoint],
        ['Parameter', vuln.parameter || 'N/A'],
        ['Method', vuln.method || 'GET'],
        ['CVE ID', vuln.cveId || 'N/A'],
        ['CVSS Score', vuln.cvssScore ? String(vuln.cvssScore) : 'N/A'],
        ['Confidence', vuln.confidence || 'N/A'],
      ];

      for (const [label, value] of details) {
        doc.fill('#8b949e').fontSize(9).font('Helvetica').text(label + ':', 60, vy);
        doc.fill('#e6edf3').fontSize(9).font('Helvetica').text(
          value.length > 80 ? value.substring(0, 80) + '…' : value,
          170, vy
        );
        vy += 14;
      }

      // Evidence
      if (vuln.evidence) {
        doc.fill('#8b949e').fontSize(9).font('Helvetica').text('Evidence:', 60, vy);
        vy += 12;
        doc.rect(60, vy, doc.page.width - 120, 1).fill('#30363d');
        vy += 4;
        
        const evidenceStr = vuln.evidence.substring(0, 300).replace(/\r?\n|\r/g, ' ');
        const textH = doc.heightOfString(evidenceStr, { width: doc.page.width - 130 });
        doc.fill('#00d4ff').fontSize(8).font('Helvetica').text(
          evidenceStr,
          65, vy, { width: doc.page.width - 130 }
        );
        vy += textH + 10;
      }

      // Recommendation
      if (vuln.recommendation) {
        doc.fill('#8b949e').fontSize(9).font('Helvetica').text('Recommendation:', 60, vy);
        vy += 12;
        
        const recStr = vuln.recommendation.replace(/\r?\n|\r/g, ' ');
        const textH = doc.heightOfString(recStr, { width: doc.page.width - 130 });
        doc.fill('#e6edf3').fontSize(8).font('Helvetica').text(
          recStr,
          65, vy, { width: doc.page.width - 130 }
        );
        vy += textH + 15;
      }

      doc.moveTo(50, vy).lineTo(doc.page.width - 50, vy).strokeColor('#30363d').lineWidth(0.5).stroke();
      vy += 15;
      vulnIndex++;
    }
  }

  addEndpointsSection(doc, scan);

  // ─── RECOMMENDATIONS SUMMARY ──────────────────────────────
  doc.addPage();
  doc.rect(0, 0, doc.page.width, doc.page.height).fill('#0d1117');
  doc.fill('#00d4ff').fontSize(20).font('Helvetica-Bold').text('REMEDIATION RECOMMENDATIONS', 50, 30);
  doc.moveTo(50, 58).lineTo(doc.page.width - 50, 58).strokeColor('#00d4ff').stroke();

  const genericRecs = [
    'Implement parameterized queries and prepared statements to prevent SQL Injection.',
    'Encode all user-supplied output and enforce a strict Content-Security-Policy.',
    'Configure all recommended security response headers on every endpoint.',
    'Ensure all administrative endpoints require valid, server-validated authentication.',
    'Validate and sanitize all file path inputs server-side to prevent path traversal.',
    'Apply input validation and output encoding as defense-in-depth measures.',
    'Regularly update all dependencies and frameworks to receive security patches.',
    'Conduct periodic penetration testing and code reviews.',
  ];

  let ry = 75;
  for (const rec of genericRecs) {
    doc.rect(50, ry, 6, 6).fill('#00d4ff');
    doc.fill('#e6edf3').fontSize(9).font('Helvetica').text(rec, 65, ry - 2, { width: doc.page.width - 115 });
    ry += 28;
  }

  // Footer
  const totalPages = doc.bufferedPageRange().count;
  for (let i = 0; i < totalPages; i++) {
    doc.switchToPage(i);
    doc.fill('#8b949e').fontSize(8).font('Helvetica').text(
      `VulnScanner Security Report  |  Confidential  |  Page ${i + 1} of ${totalPages}`,
      50, doc.page.height - 30, { align: 'center', width: doc.page.width - 100 }
    );
  }

  return doc;
}

module.exports = { generatePDF };
