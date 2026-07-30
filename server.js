const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || ROOT;
const DB_FILE = path.join(DATA_DIR, 'didiscord-db.json');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.webp': 'image/webp',
};

function hashPassword(password) {
  return crypto.createHash('sha256').update(String(password)).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(24).toString('hex');
}

function createDb() {
  return { accounts: {}, sessions: {}, leaderboard: [] };
}

function loadDb() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const db = createDb();
      fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
      return db;
    }
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const db = JSON.parse(raw || '{}');
    if (!db.accounts) db.accounts = {};
    if (!db.sessions) db.sessions = {};
    if (!db.leaderboard) db.leaderboard = [];
    return db;
  } catch {
    const db = createDb();
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return db;
  }
}

function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data));
}

function sendFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) {
        reject(new Error('Body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function getUsernameByToken(db, token) {
  return db.sessions[token] || null;
}

function rebuildLeaderboard(db) {
  db.leaderboard = Object.values(db.accounts)
    .map(acc => ({
      name: acc.username,
      coins: Math.floor(acc.gameState?.coins || 0),
      income: Math.round((acc.income || 0) * 10) / 10,
      sticks: Array.isArray(acc.gameState?.inventory) ? acc.gameState.inventory.length : 0,
    }))
    .sort((a, b) => b.coins - a.coins)
    .slice(0, 50);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const urlPath = decodeURIComponent(url.pathname);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  if (urlPath === '/api/status' && req.method === 'GET') {
    sendJson(res, 200, { ok: true, mode: 'backend' });
    return;
  }

  if (urlPath === '/api/register' && req.method === 'POST') {
    try {
      const db = loadDb();
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!username) return sendJson(res, 400, { ok: false, message: 'Zadej uživatelské jméno.' });
      if (password.length < 3) return sendJson(res, 400, { ok: false, message: 'Heslo musí mít alespoň 3 znaky.' });
      const key = username.toLowerCase();
      if (db.accounts[key]) return sendJson(res, 409, { ok: false, message: `Uživatel "${username}" už existuje!` });

      db.accounts[key] = {
        username,
        passHash: hashPassword(password),
        gameState: body.gameState || {},
        income: 0,
        lastUpdate: Date.now(),
      };
      const token = randomToken();
      db.sessions[token] = key;
      rebuildLeaderboard(db);
      saveDb(db);
      sendJson(res, 200, { ok: true, token, gameState: db.accounts[key].gameState, username });
    } catch (e) {
      sendJson(res, 500, { ok: false, message: 'Registrace se nepodařila.' });
    }
    return;
  }

  if (urlPath === '/api/login' && req.method === 'POST') {
    try {
      const db = loadDb();
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const key = username.toLowerCase();
      const account = db.accounts[key];
      if (!account) return sendJson(res, 404, { ok: false, message: `Uživatel "${username}" neexistuje.` });
      if (account.passHash !== hashPassword(password)) return sendJson(res, 401, { ok: false, message: 'Špatné heslo!' });
      const token = randomToken();
      db.sessions[token] = key;
      saveDb(db);
      sendJson(res, 200, { ok: true, token, gameState: account.gameState, username: account.username });
    } catch {
      sendJson(res, 500, { ok: false, message: 'Přihlášení se nepodařilo.' });
    }
    return;
  }

  if (urlPath === '/api/state' && req.method === 'GET') {
    const token = String(url.searchParams.get('token') || '');
    const db = loadDb();
    const key = getUsernameByToken(db, token);
    if (!key || !db.accounts[key]) return sendJson(res, 401, { ok: false, message: 'Neplatná session.' });
    sendJson(res, 200, { ok: true, gameState: db.accounts[key].gameState, username: db.accounts[key].username });
    return;
  }

  if (urlPath === '/api/save' && req.method === 'POST') {
    try {
      const db = loadDb();
      const body = await readBody(req);
      const token = String(body.token || '');
      const key = getUsernameByToken(db, token);
      if (!key || !db.accounts[key]) return sendJson(res, 401, { ok: false, message: 'Neplatná session.' });
      db.accounts[key].gameState = body.gameState || db.accounts[key].gameState;
      db.accounts[key].income = Number(body.income || 0);
      db.accounts[key].lastUpdate = Date.now();
      rebuildLeaderboard(db);
      saveDb(db);
      sendJson(res, 200, { ok: true, leaderboard: db.leaderboard });
    } catch {
      sendJson(res, 500, { ok: false, message: 'Uložení se nepodařilo.' });
    }
    return;
  }

  if (urlPath === '/api/leaderboard' && req.method === 'GET') {
    const db = loadDb();
    rebuildLeaderboard(db);
    saveDb(db);
    sendJson(res, 200, { ok: true, leaderboard: db.leaderboard });
    return;
  }

  if (urlPath === '/api/account/username' && req.method === 'POST') {
    try {
      const db = loadDb();
      const body = await readBody(req);
      const token = String(body.token || '');
      const newUsername = String(body.newUsername || '').trim();
      const oldKey = getUsernameByToken(db, token);
      if (!oldKey || !db.accounts[oldKey]) return sendJson(res, 401, { ok: false, message: 'Neplatná session.' });
      if (!newUsername) return sendJson(res, 400, { ok: false, message: 'Zadej nové jméno.' });
      const newKey = newUsername.toLowerCase();
      if (newKey !== oldKey && db.accounts[newKey]) return sendJson(res, 409, { ok: false, message: `Jméno "${newUsername}" je už zabrané.` });
      const acc = db.accounts[oldKey];
      delete db.accounts[oldKey];
      acc.username = newUsername;
      db.accounts[newKey] = acc;
      Object.keys(db.sessions).forEach(session => {
        if (db.sessions[session] === oldKey) db.sessions[session] = newKey;
      });
      rebuildLeaderboard(db);
      saveDb(db);
      sendJson(res, 200, { ok: true, username: newUsername });
    } catch {
      sendJson(res, 500, { ok: false, message: 'Změna jména se nepodařila.' });
    }
    return;
  }

  if (urlPath === '/api/account/password' && req.method === 'POST') {
    try {
      const db = loadDb();
      const body = await readBody(req);
      const token = String(body.token || '');
      const oldPassword = String(body.oldPassword || '');
      const newPassword = String(body.newPassword || '');
      const key = getUsernameByToken(db, token);
      if (!key || !db.accounts[key]) return sendJson(res, 401, { ok: false, message: 'Neplatná session.' });
      if (newPassword.length < 3) return sendJson(res, 400, { ok: false, message: 'Nové heslo musí mít min. 3 znaky.' });
      const acc = db.accounts[key];
      if (acc.passHash !== hashPassword(oldPassword)) return sendJson(res, 401, { ok: false, message: 'Staré heslo je špatně!' });
      acc.passHash = hashPassword(newPassword);
      saveDb(db);
      sendJson(res, 200, { ok: true });
    } catch {
      sendJson(res, 500, { ok: false, message: 'Změna hesla se nepodařila.' });
    }
    return;
  }

  if (urlPath === '/api/account/delete' && req.method === 'POST') {
    try {
      const db = loadDb();
      const body = await readBody(req);
      const token = String(body.token || '');
      const key = getUsernameByToken(db, token);
      if (!key || !db.accounts[key]) return sendJson(res, 401, { ok: false, message: 'Neplatná session.' });
      delete db.accounts[key];
      Object.keys(db.sessions).forEach(session => {
        if (db.sessions[session] === key) delete db.sessions[session];
      });
      rebuildLeaderboard(db);
      saveDb(db);
      sendJson(res, 200, { ok: true });
    } catch {
      sendJson(res, 500, { ok: false, message: 'Smazání účtu se nepodařilo.' });
    }
    return;
  }

  const filePath = path.join(ROOT, urlPath === '/' ? 'index.html' : urlPath);
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('403 Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (!err && stats.isFile()) {
      sendFile(res, filePath);
      return;
    }
    sendFile(res, path.join(ROOT, 'index.html'));
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Didiscord server running on port ${PORT}`);
});
