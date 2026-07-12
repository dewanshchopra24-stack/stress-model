// StressMap backend — zero external dependencies (pure Node.js core modules only)
// Runs with: node server.js
// Needs Node.js v22.5+ (uses the built-in node:sqlite module)

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'stressmap.db');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const COOKIE_NAME = 'stressmap_session';

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    name_lower TEXT NOT NULL UNIQUE,
    mobile TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    exam_type TEXT,
    total INTEGER,
    pct INTEGER,
    grade TEXT,
    cat_scores TEXT,
    created_at INTEGER NOT NULL
  );
`);

// ---------------------------------------------------------------------------
// Password hashing (scrypt, built into Node's crypto module — no bcrypt needed)
// ---------------------------------------------------------------------------
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function makeSalt() {
  return crypto.randomBytes(16).toString('hex');
}

function verifyPassword(password, salt, hash) {
  const check = hashPassword(password, salt);
  const a = Buffer.from(check, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1e6) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare(
    'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).run(token, userId, now, now + SESSION_TTL_MS);
  return token;
}

function getUserFromRequest(req) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  const session = db
    .prepare('SELECT * FROM sessions WHERE token = ?')
    .get(token);
  if (!session) return null;
  if (session.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  const user = db
    .prepare('SELECT id, name, mobile, created_at FROM users WHERE id = ?')
    .get(session.user_id);
  return user || null;
}

function setSessionCookie(res, token) {
  const expires = new Date(Date.now() + SESSION_TTL_MS).toUTCString();
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${token}; HttpOnly; Path=/; SameSite=Lax; Expires=${expires}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
  );
}

const MOBILE_RE = /^[6-9]\d{9}$/;

// ---------------------------------------------------------------------------
// API route handlers
// ---------------------------------------------------------------------------
async function handleRegister(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: 'Invalid request body.' });
  }
  const name = (body.name || '').toString().trim();
  const mobile = (body.mobile || '').toString().trim();
  const password = (body.password || '').toString();

  if (name.length < 2) {
    return sendJson(res, 400, { error: 'Please enter your full name.' });
  }
  if (!MOBILE_RE.test(mobile)) {
    return sendJson(res, 400, { error: 'Enter a valid 10-digit mobile number.' });
  }
  if (password.length < 6) {
    return sendJson(res, 400, { error: 'Password must be at least 6 characters.' });
  }

  const nameLower = name.toLowerCase();
  const existingName = db
    .prepare('SELECT id FROM users WHERE name_lower = ?')
    .get(nameLower);
  if (existingName) {
    return sendJson(res, 409, {
      error: 'That name is already registered. Try logging in, or use a slightly different name.',
    });
  }
  const existingMobile = db
    .prepare('SELECT id FROM users WHERE mobile = ?')
    .get(mobile);
  if (existingMobile) {
    return sendJson(res, 409, { error: 'This mobile number is already registered.' });
  }

  const salt = makeSalt();
  const hash = hashPassword(password, salt);
  const now = Date.now();
  const info = db
    .prepare(
      'INSERT INTO users (name, name_lower, mobile, salt, hash, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    )
    .run(name, nameLower, mobile, salt, hash, now);

  const token = createSession(Number(info.lastInsertRowid));
  setSessionCookie(res, token);
  sendJson(res, 201, { id: info.lastInsertRowid, name, mobile });
}

async function handleLogin(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: 'Invalid request body.' });
  }
  const name = (body.name || '').toString().trim();
  const password = (body.password || '').toString();

  if (!name || !password) {
    return sendJson(res, 400, { error: 'Enter your name and password.' });
  }

  const user = db
    .prepare('SELECT * FROM users WHERE name_lower = ?')
    .get(name.toLowerCase());

  // Deliberately vague error so we don't reveal whether the name exists.
  if (!user || !verifyPassword(password, user.salt, user.hash)) {
    return sendJson(res, 401, { error: 'Incorrect name or password.' });
  }

  const token = createSession(user.id);
  setSessionCookie(res, token);
  sendJson(res, 200, { id: user.id, name: user.name, mobile: user.mobile });
}

function handleLogout(req, res) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
}

function handleMe(req, res) {
  const user = getUserFromRequest(req);
  if (!user) return sendJson(res, 401, { error: 'Not logged in.' });
  sendJson(res, 200, { id: user.id, name: user.name, mobile: user.mobile });
}

async function handleSaveResult(req, res) {
  const user = getUserFromRequest(req);
  if (!user) return sendJson(res, 401, { error: 'Not logged in.' });
  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: 'Invalid request body.' });
  }
  const { examType, total, pct, grade, catScores } = body;
  db.prepare(
    'INSERT INTO results (user_id, exam_type, total, pct, grade, cat_scores, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(
    user.id,
    String(examType || ''),
    Number(total) || 0,
    Number(pct) || 0,
    String(grade || ''),
    JSON.stringify(catScores || {}),
    Date.now()
  );
  sendJson(res, 201, { ok: true });
}

function handleHistory(req, res) {
  const user = getUserFromRequest(req);
  if (!user) return sendJson(res, 401, { error: 'Not logged in.' });
  const rows = db
    .prepare(
      'SELECT id, exam_type, total, pct, grade, cat_scores, created_at FROM results WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
    )
    .all(user.id);
  const parsed = rows.map((r) => ({
    ...r,
    cat_scores: JSON.parse(r.cat_scores || '{}'),
  }));
  sendJson(res, 200, { results: parsed });
}

// ---------------------------------------------------------------------------
// Static file serving
// ---------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.normalize(filePath).replace(/^(\.\.[/\\])+/, '');
  let fullPath = path.join(PUBLIC_DIR, filePath);

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      // SPA fallback for unknown, extension-less routes
      if (!path.extname(filePath)) {
        return fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, data2) => {
          if (err2) return sendJson(res, 404, { error: 'Not found.' });
          res.writeHead(200, { 'Content-Type': MIME['.html'] });
          res.end(data2);
        });
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(fullPath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  res.setHeader('X-Content-Type-Options', 'nosniff');

  try {
    if (pathname === '/api/register' && req.method === 'POST') {
      return await handleRegister(req, res);
    }
    if (pathname === '/api/login' && req.method === 'POST') {
      return await handleLogin(req, res);
    }
    if (pathname === '/api/logout' && req.method === 'POST') {
      return handleLogout(req, res);
    }
    if (pathname === '/api/me' && req.method === 'GET') {
      return handleMe(req, res);
    }
    if (pathname === '/api/results' && req.method === 'POST') {
      return await handleSaveResult(req, res);
    }
    if (pathname === '/api/results' && req.method === 'GET') {
      return handleHistory(req, res);
    }
    if (pathname.startsWith('/api/')) {
      return sendJson(res, 404, { error: 'Unknown API route.' });
    }
    return serveStatic(req, res, pathname);
  } catch (err) {
    console.error(err);
    return sendJson(res, 500, { error: 'Something went wrong on our end.' });
  }
});

server.listen(PORT, () => {
  console.log(`StressMap server running at http://localhost:${PORT}`);
  console.log(`Database file: ${DB_PATH}`);
});
