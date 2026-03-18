const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');

// GET /api/results — return all scans with summary
router.get('/results', async (req, res) => {
  try {
    const scans = await Scan.find().sort({ createdAt: -1 }).limit(50);
    res.json(scans);
  } catch (err) {
    console.error('[Route /results]', err.message);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/results/:id — return scan details + vulnerabilities
router.get('/results/:id', async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found.' });
    }

    const vulnerabilities = await Vulnerability.find({ scanId: req.params.id }).sort({ timestamp: -1 });

    res.json({
      scan,
      vulnerabilities,
    });
  } catch (err) {
    console.error('[Route /results/:id]', err.message);
    if (err.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid scan ID format.' });
    }
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
