const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_PATH = path.join(__dirname, 'rates.json');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'korviana123';

function hashPassword(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  const allowedOrigins = new Set([
    'https://korviana.in',
    'https://www.korviana.in',
    'https://itwebdev2026-cloud.github.io',
    'http://localhost:8000',
    'http://localhost:3000'
  ]);
  const origin = req.headers.origin;
  if (allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  next();
});
app.use(session({
  secret: process.env.SESSION_SECRET || 'korviana-admin-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false }
}));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    return res.json({ success: true });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/session', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.isAdmin) });
});

app.get('/api/rates', (req, res) => {
  try {
    const raw = fs.readFileSync(DATA_PATH, 'utf8');
    const data = JSON.parse(raw);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Unable to read rates.json' });
  }
});

app.post('/api/rates', requireAdmin, (req, res) => {
  try {
    const incoming = req.body;
    if (!incoming || typeof incoming !== 'object') {
      return res.status(400).json({ error: 'Invalid payload' });
    }

    const current = fs.existsSync(DATA_PATH)
      ? JSON.parse(fs.readFileSync(DATA_PATH, 'utf8'))
      : { Gold: {}, Silver: {} };

    const merged = {
      Gold: { ...(current.Gold || {}), ...(incoming.Gold || {}) },
      Silver: { ...(current.Silver || {}), ...(incoming.Silver || {}) }
    };

    fs.writeFileSync(DATA_PATH, JSON.stringify(merged, null, 2) + '\n');
    res.json({ success: true, data: merged });
  } catch (error) {
    res.status(500).json({ error: 'Unable to save rates' });
  }
});

app.use(express.static(__dirname));

app.get('/p.html', (req, res) => {
  if (req.session && req.session.isAdmin) {
    return res.sendFile(path.join(__dirname, 'p.html'));
  }
  return res.redirect('/admin');
});

app.get('/admin', (req, res) => {
  if (req.session && req.session.isAdmin) {
    return res.sendFile(path.join(__dirname, 'p.html'));
  }
  return res.sendFile(path.join(__dirname, 'admin-login.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Admin login: username=${ADMIN_USERNAME}, password=${ADMIN_PASSWORD}`);
});
