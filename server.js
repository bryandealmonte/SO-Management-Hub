require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const axios   = require('axios');
const cors    = require('cors');
const path    = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const ACCOUNT_ID = (process.env.NS_ACCOUNT_ID || '').toLowerCase().replace(/_/g, '-');
const NS_BASE = process.env.NS_BASE_URL || `https://${ACCOUNT_ID}.app.netsuite.com/services/rest`;

console.log(`NS_ACCOUNT_ID: ${process.env.NS_ACCOUNT_ID}`);
console.log(`NS_BASE: ${NS_BASE}`);

// Direct axios request — app.netsuite.com resolves fine via standard DNS.
async function nsRequest(method, url, data, headers) {
  return axios({ method, url, data, headers, timeout: 30000 });
}

const enc = s => encodeURIComponent(String(s));

function oauthHeader(method, baseUrl, queryParams = {}) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const nc = crypto.randomBytes(16).toString('hex');
  const oParams = {
    oauth_consumer_key:     process.env.NS_CONSUMER_KEY,
    oauth_nonce:            nc,
    oauth_signature_method: 'HMAC-SHA256',
    oauth_timestamp:        ts,
    oauth_token:            process.env.NS_TOKEN_KEY,
    oauth_version:          '1.0',
  };
  const all = { ...queryParams, ...oParams };
  const paramStr = Object.keys(all).sort()
    .map(k => `${enc(k)}=${enc(all[k])}`).join('&');
  const base = `${method.toUpperCase()}&${enc(baseUrl)}&${enc(paramStr)}`;
  const key  = `${enc(process.env.NS_CONSUMER_SECRET)}&${enc(process.env.NS_TOKEN_SECRET)}`;
  const sig  = crypto.createHmac('sha256', key).update(base).digest('base64');
  oParams.oauth_signature = sig;
  return `OAuth realm="${process.env.NS_ACCOUNT_ID}",` +
    Object.keys(oParams).map(k => `${k}="${enc(oParams[k])}"`).join(',');
}

// GET /debug
app.get('/debug', (req, res) => {
  const peek = v => v ? `${v.slice(0,4)}...${v.slice(-4)} (len:${v.length})` : 'NOT SET';
  res.json({
    NS_BASE, ACCOUNT_ID,
    NS_ACCOUNT_ID:      process.env.NS_ACCOUNT_ID,
    NS_CONSUMER_KEY:    peek(process.env.NS_CONSUMER_KEY),
    NS_CONSUMER_SECRET: peek(process.env.NS_CONSUMER_SECRET),
    NS_TOKEN_KEY:       peek(process.env.NS_TOKEN_KEY),
    NS_TOKEN_SECRET:    peek(process.env.NS_TOKEN_SECRET),
  });
});

// POST /suiteql
app.post('/suiteql', async (req, res) => {
  const { query, limit = 1000, offset = 0 } = req.body;
  if (!query) return res.status(400).json({ error: 'query is required' });
  const baseUrl = `${NS_BASE}/query/v1/suiteql`;
  const fullUrl = `${baseUrl}?limit=${limit}&offset=${offset}`;
  try {
    const r = await nsRequest('POST', fullUrl, { q: query }, {
      Authorization:  oauthHeader('POST', baseUrl, { limit: String(limit), offset: String(offset) }),
      'Content-Type': 'application/json',
      Prefer:         'transient',
    });
    res.json(r.data);
  } catch (e) {
    const detail = e.response?.data || e.message;
    console.error('SuiteQL error:', JSON.stringify(detail));
    res.status(500).json({ error: detail });
  }
});

// PATCH /record/:type/:id
app.patch('/record/:type/:id', async (req, res) => {
  const { type, id } = req.params;
  const url = `${NS_BASE}/record/v1/${type}/${id}`;
  try {
    await nsRequest('PATCH', url, req.body, {
      Authorization:  oauthHeader('PATCH', url),
      'Content-Type': 'application/json',
    });
    res.json({ success: true });
  } catch (e) {
    const detail = e.response?.data || e.message;
    console.error('Record update error:', JSON.stringify(detail));
    res.status(500).json({ error: detail });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SO Calendar server running on :${PORT}`));
