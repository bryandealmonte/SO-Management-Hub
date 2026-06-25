require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const axios   = require('axios');
const cors    = require('cors');
const path    = require('path');
const dns     = require('dns').promises;

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const ACCOUNT_ID = (process.env.NS_ACCOUNT_ID || '').toLowerCase().replace(/_/g, '-');
const NS_BASE = process.env.NS_BASE_URL || `https://${ACCOUNT_ID}.suiteanalytics.com/services/rest`;

console.log(`NS_ACCOUNT_ID: ${process.env.NS_ACCOUNT_ID}`);
console.log(`NS_BASE: ${NS_BASE}`);

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
  const paramStr = Object.keys(all).sort().map(k => `${enc(k)}=${enc(all[k])}`).join('&');
  const base = `${method.toUpperCase()}&${enc(baseUrl)}&${enc(paramStr)}`;
  const key  = `${enc(process.env.NS_CONSUMER_SECRET)}&${enc(process.env.NS_TOKEN_SECRET)}`;
  const sig  = crypto.createHmac('sha256', key).update(base).digest('base64');
  oParams.oauth_signature = sig;
  return `OAuth realm="${process.env.NS_ACCOUNT_ID}",` + Object.keys(oParams).map(k => `${k}="${enc(oParams[k])}"`).join(',');
}

app.get('/debug', async (req, res) => {
  const hostname = `${ACCOUNT_ID}.suiteanalytics.com`;
  const results = { NS_BASE, hostname, ACCOUNT_ID };
  try { const a = await dns.resolve(hostname); results.dns = { ok: true, addresses: a }; }
  catch (e) { results.dns = { ok: false, error: e.message }; }
  try { await dns.resolve('google.com'); results.outbound = { ok: true }; }
  catch (e) { results.outbound = { ok: false, error: e.message }; }
  res.json(results);
});

app.post('/suiteql', async (req, res) => {
  const { query, limit = 1000, offset = 0 } = req.body;
  if (!query) return res.status(400).json({ error: 'query is required' });
  const baseUrl = `${NS_BASE}/query/v1/suiteql`;
  const fullUrl = `${baseUrl}?limit=${limit}&offset=${offset}`;
  try {
    const r = await axios.post(fullUrl, { q: query }, {
      headers: {
        Authorization:  oauthHeader('POST', baseUrl, { limit: String(limit), offset: String(offset) }),
        'Content-Type': 'application/json',
        Prefer:         'transient',
      },
      timeout: 30000,
    });
    res.json(r.data);
  } catch (e) {
    const detail = e.response?.data || e.message;
    console.error('SuiteQL error:', JSON.stringify(detail));
    res.status(500).json({ error: detail });
  }
});

app.patch('/record/:type/:id', async (req, res) => {
  const { type, id } = req.params;
  const url = `${NS_BASE}/record/v1/${type}/${id}`;
  try {
    await axios.patch(url, req.body, {
      headers: { Authorization: oauthHeader('PATCH', url), 'Content-Type': 'application/json' },
      timeout: 30000,
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
