const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

// We need to set a dummy secret/url for tests before requiring app
process.env.MONGO_URI = 'mongodb://dummy';
process.env.FRONTEND_URL = '*';
process.env.PORT = 5005;

const Scan = require('../models/Scan');
const Vulnerability = require('../models/Vulnerability');

// Mock the scannerService so it doesn't actually run external HTTP requests during tests
jest.mock('../services/scannerService', () => ({
  startScan: jest.fn().mockResolvedValue(),
}));

let mongoServer;
let app;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGO_URI = mongoServer.getUri();
  
  const serverModule = require('../server');
  app = serverModule.app;
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await Scan.deleteMany({});
  await Vulnerability.deleteMany({});
});

describe('API Routes', () => {
  describe('GET /api/health', () => {
    test('returns 200 OK', async () => {
      const res = await request(app).get('/api/health');
      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('status', 'ok');
    });
  });

  describe('POST /api/scan', () => {
    test('rejects missing url', async () => {
      const res = await request(app).post('/api/scan').send({});
      expect(res.statusCode).toBe(400);
      expect(res.body.error).toContain('valid target URL');
    });

    test('rejects invalid url format', async () => {
      const res = await request(app).post('/api/scan').send({ url: 'not-a-url' });
      expect(res.statusCode).toBe(400);
      expect(res.body.error).toContain('Invalid URL format');
    });

    test('accepts valid url and creates scan record', async () => {
      const url = 'http://example.com';
      const res = await request(app).post('/api/scan').send({ url });
      
      expect(res.statusCode).toBe(201);
      expect(res.body).toHaveProperty('scanId');
      expect(res.body.targetUrl).toBe(url);

      // Verify db
      const dbScan = await Scan.findById(res.body.scanId);
      expect(dbScan).not.toBeNull();
      expect(dbScan.targetUrl).toBe(url);
      expect(dbScan.status).toBe('queued');
    });
  });

  describe('GET /api/scans', () => {
    test('returns empty array when no scans', async () => {
      const res = await request(app).get('/api/scans');
      expect(res.statusCode).toBe(200);
      expect(res.body).toBeInstanceOf(Array);
      expect(res.body.length).toBe(0);
    });

    test('returns list of scans', async () => {
      await Scan.create({ targetUrl: 'http://foo.com', status: 'completed' });
      await Scan.create({ targetUrl: 'http://bar.com', status: 'running' });

      const res = await request(app).get('/api/scans');
      expect(res.statusCode).toBe(200);
      expect(res.body.length).toBe(2);
      expect(res.body[0].targetUrl).toBe('http://bar.com'); // sorted by createdAt desc
    });
  });

  describe('GET /api/results/:id', () => {
    test('returns 404 for invalid scan ID format', async () => {
      const res = await request(app).get('/api/results/invalid-id');
      expect(res.statusCode).toBe(400);
    });

    test('returns 404 for non-existent scan', async () => {
      const dummyId = new mongoose.Types.ObjectId();
      const res = await request(app).get(`/api/results/${dummyId}`);
      expect(res.statusCode).toBe(404);
    });

    test('returns scan and its vulnerabilities', async () => {
      const scan = await Scan.create({ targetUrl: 'http://foo.com', status: 'completed' });
      const vuln = await Vulnerability.create({
        scanId: scan._id,
        type: 'XSS',
        severity: 'High',
        endpoint: 'http://foo.com/search',
      });

      const res = await request(app).get(`/api/results/${scan._id}`);
      expect(res.statusCode).toBe(200);
      expect(res.body.scan._id).toBe(scan._id.toString());
      expect(res.body.vulnerabilities.length).toBe(1);
      expect(res.body.vulnerabilities[0].type).toBe('XSS');
    });
  });
});
