const mongoose = require('mongoose');

const ScanSchema = new mongoose.Schema({
  targetUrl: {
    type: String,
    required: true,
    trim: true,
  },
  status: {
    type: String,
    enum: ['queued', 'running', 'completed', 'failed'],
    default: 'queued',
  },
  progress: {
    type: Number,
    default: 0,
    min: 0,
    max: 100,
  },
  currentActivity: {
    type: String,
    default: 'Initializing scan...',
  },
  totalEndpoints: {
    type: Number,
    default: 0,
  },
  scannedEndpoints: {
    type: Number,
    default: 0,
  },
  summary: {
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    info: { type: Number, default: 0 },
    total: { type: Number, default: 0 },
  },
  error: {
    type: String,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  completedAt: {
    type: Date,
    default: null,
  },
});

module.exports = mongoose.model('Scan', ScanSchema);
