require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const mongoose = require('mongoose');

const scanRoutes = require('./routes/scan');
const resultsRoutes = require('./routes/results');
const reportRoutes = require('./routes/report');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST'],
  },
});

// Make io accessible to routes/services
app.set('io', io);

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Routes
app.use('/api', scanRoutes);
app.use('/api', resultsRoutes);
app.use('/api', reportRoutes);

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);
  socket.on('join_scan', (scanId) => {
    socket.join(scanId);
    console.log(`[Socket.IO] Client ${socket.id} joined room: ${scanId}`);
  });
  socket.on('disconnect', () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://mongodb:27017/vulnscanner';

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('[DB] Connected to MongoDB:', MONGO_URI);
    const PORT = process.env.PORT || 5000;
    server.listen(PORT, () => {
      console.log(`[Server] VulnScanner API running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('[DB] MongoDB connection failed:', err.message);
    process.exit(1);
  });

module.exports = { app, io };
