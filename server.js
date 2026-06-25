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

const ACCOUNT_ID = (process.env.NS_ACCOUNT_ID || '').toUpperCase();
const NS_BASE = process.env.NS_BASE_URL || ('https://' + ACCOUNT_ID.toLowerCase().replace(/_/g,'-') + '.app.netsuite.com/services/rest');

console.log('NS_ACCOUNT_ID:', process.env.NS_ACCOUNT_ID);
console.log('NS_BASE:', NS_BASE);

async function nsRequest(method, url, data, headers) {
  return axios({ method, url, data, headers, timeout: 30000 });
}

const enc = s => encodeURIComponent(String(s));

function oauthHeader(method, baseUrl, queryParams) {
  queryParams = queryParams || {};
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
  const all = Object.assign({}, queryParams, oParams);
  const paramStr = Object.keys(all).sort()
    .map(function(k){ return enc(k) + '=' + enc(all[k]); }).join('&');
  const base = method.toUpperCase() + '&' + enc(baseUrl) + '&' + enc(paramStr);
  const key  = enc(process.env.NS_CONSUMER_SECRET) + '&' + enc(process.env.NS_TOKEN_SECRET);
  const sig  = crypto.createHmac('sha256', key).update(base).digest('base64');
  oParams.oauth_signature = sig;
  const headerParts = Object.keys(oParams).map(function(k){
    return k + '="' + enc(oParams[k]) + '"';
  });
  return 'OAuth realm="' + process.env.NS_ACCOUNT_ID + '", ' + headerParts.join(', ');
}

// GET /debug
app.get('/debug', function(req, res) {
  const peek = function(v){ return v ? v.slice(0,4)+'...'+v.slice(-4)+' (len:'+v.length+')' : 'NOT SET'; };
  res.json({
    NS_BASE: NS_BASE,
    ACCOUNT_ID: ACCOUNT_ID,
    NS_ACCOUNT_ID:      process.env.NS_ACCOUNT_ID,
    NS_CONSUMER_KEY:    peek(process.env.NS_CONSUMER_KEY),
    NS_CONSUMER_SECRET: peek(process.env.NS_CONSUMER_SECRET),
    NS_TOKEN_KEY:       peek(process.env.NS_TOKEN_KEY),
    NS_TOKEN_SECRET:    peek(process.env.NS_TOKEN_SECRET),
  });
});

// POST /suiteql
app.post('/suiteql', async function(req, res) {
  const query  = req.body.query;
  const limit  = req.body.limit  || 1000;
  const offset = req.body.offset || 0;
  if (!query) return res.status(400).json({ error: 'query is required' });
  const baseUrl = NS_BASE + '/query/v1/suiteql';
  const fullUrl = baseUrl + '?limit=' + limit + '&offset=' + offset;
  try {
    const r = await nsRequest('POST', fullUrl, { q: query }, {
      Authorization:  oauthHeader('POST', baseUrl, { limit: String(limit), offset: String(offset) }),
      'Content-Type': 'application/json',
      Prefer:         'transient',
    });
    res.json(r.data);
  } catch (e) {
    const detail = e.response ? e.response.data : e.message;
    console.error('SuiteQL error:', JSON.stringify(detail));
    res.status(500).json({ error: detail });
  }
});

// PATCH /record/:type/:id
app.patch('/record/:type/:id', async function(req, res) {
  const type = req.params.type;
  const id   = req.params.id;
  const url  = NS_BASE + '/record/v1/' + type + '/' + id;
  try {
    await nsRequest('PATCH', url, req.body, {
      Authorization:  oauthHeader('PATCH', url),
      'Content-Type': 'application/json',
    });
    res.json({ success: true });
  } catch (e) {
    const detail = e.response ? e.response.data : e.message;
    console.error('Record update error:', JSON.stringify(detail));
    res.status(500).json({ error: detail });
  }
});

app.get('*', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function(){ console.log('SO Calendar server running on :' + PORT); });
