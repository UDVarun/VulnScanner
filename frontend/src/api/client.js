import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

export const startScan = (url) => client.post('/api/scan', { url });
export const getScans = () => client.get('/api/scans');
export const getResults = (id) => client.get(`/api/results/${id}`);
export const getReportUrl = (id) => `${API_BASE}/api/report/${id}`;

export default client;
