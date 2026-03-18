const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const { startScan } = require('../services/scannerService');

// POST /api/scan — start a new scan
router.post('/scan', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'A valid target URL is required.' });
    }

    // Basic URL validation
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format. Please include protocol (http:// or https://).' });
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Only HTTP and HTTPS protocols are supported.' });
    }

    // Create scan record
    const scan = new Scan({
      targetUrl: url,
      status: 'queued',
      currentActivity: 'Scan queued...',
    });
    await scan.save();

    const io = req.app.get('io');

    // Start scan asynchronously (non-blocking)
    startScan(scan._id.toString(), url, io).catch((err) => {
      console.error(`[ScanService] Scan ${scan._id} failed:`, err.message);
    });

    res.status(201).json({
      scanId: scan._id,
      message: 'Scan started successfully.',
      targetUrl: url,
    });
  } catch (err) {
    console.error('[Route /scan]', err.message);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/scans — list all scans
router.get('/scans', async (req, res) => {
  try {
    const scans = await Scan.find().sort({ createdAt: -1 }).limit(50);
    res.json(scans);
  } catch (err) {
    console.error('[Route /scans]', err.message);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
