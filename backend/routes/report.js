const express = require('express');
const router = express.Router();
const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');
const { generatePDF } = require('../engines/reportEngine');

// GET /api/report/:id — generate and stream PDF report
router.get('/report/:id', async (req, res) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found.' });
    }

    const vulnerabilities = await Vulnerability.find({ scanId: req.params.id }).sort({ severity: 1 });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="vulnscanner-report-${req.params.id}.pdf"`
    );

    const pdfStream = generatePDF(scan, vulnerabilities);
    pdfStream.pipe(res);
    pdfStream.end();
  } catch (err) {
    console.error('[Route /report/:id]', err.message);
    if (err.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid scan ID format.' });
    }
    res.status(500).json({ error: 'Failed to generate report.' });
  }
});

module.exports = router;
