// ═══════════════════════════════════════════════
//  Apply API — Backend Real (Node.js + Express)
// ═══════════════════════════════════════════════

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app      = express();
const PORT     = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE  = path.join(DATA_DIR, 'db.json');

app.use(cors({ origin: '*' }));
app.use(express.json());

// ── DB helpers ──────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return { users:{}, tokens:{}, collections:{}, records:{} };
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch { return { users:{}, tokens:{}, collections:{}, records:{} }; }
}

function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function uid()   { return 'rec_' + crypto.randomBytes(8).toString('hex'); }
function genTk() { return 'apl_' + crypto.randomBytes(20).toString('hex'); }
function hash(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// ── Auth Middleware ──────────────────────────────
function auth(req, res, next) {
  const raw   = req.headers.authorization || '';
  const token = raw.replace(/^Bearer /i,'').trim() || req.query.token || '';
  if (!token) return res.status(401).json({ error:'Token obrigatório', status:401 });
  const db = readDB();
  const tk = db.tokens[token];
  if (!tk) return res.status(401).json({ error:'Token inválido ou revogado', status:401 });
  req.tk = tk;
  next();
}

// ── Serve frontend HTML ──────────────────────────
app.get('/', (req, res) => {
  const f = path.join(__dirname, 'apply.html');
  if (fs.existsSync(f)) res.sendFile(f);
  else res.json({ service:'Apply API', version:'1.0', status:'running' });
});

// ── AUTH ────────────────────────────────────────

app.post('/auth/register', (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password) return res.status(400).json({ error:'Email e password obrigatórios' });
  const db = readDB();
  if (db.users[email]) return res.status(409).json({ error:'Email já registado — usa /auth/login' });
  const userId = uid();
  db.users[email] = { id:userId, email, name: name||email.split('@')[0], hash: hash(email+':'+password), created: Date.now() };
  const tokenKey = genTk();
  db.tokens[tokenKey] = { key:tokenKey, name:'Token Principal', userId, perms:'rw', created: Date.now() };
  if (!db.collections) db.collections = {};
  if (!db.records)     db.records     = {};
  writeDB(db);
  res.status(201).json({ user:{ email, name:db.users[email].name }, token:tokenKey });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const db = readDB();
  const user = db.users[email];
  if (!user || user.hash !== hash(email+':'+password))
    return res.status(401).json({ error:'Email ou password incorretos' });
  const tokens = Object.values(db.tokens).filter(t => t.userId === user.id);
  res.json({ user:{ email, name:user.name }, tokens });
});

// ── TOKENS ──────────────────────────────────────

app.get('/tokens', auth, (req, res) => {
  const db = readDB();
  const tokens = Object.values(db.tokens).filter(t => t.userId === req.tk.userId);
  res.json({ tokens });
});

app.post('/tokens', auth, (req, res) => {
  const { name, perms } = req.body || {};
  const db = readDB();
  const key = genTk();
  db.tokens[key] = { key, name: name||'Novo Token', userId: req.tk.userId, perms: perms||'rw', created: Date.now() };
  writeDB(db);
  res.status(201).json(db.tokens[key]);
});

app.delete('/tokens/:key', auth, (req, res) => {
  const db = readDB();
  const tk = db.tokens[req.params.key];
  if (!tk || tk.userId !== req.tk.userId) return res.status(404).json({ error:'Token não encontrado' });
  delete db.tokens[req.params.key];
  writeDB(db);
  res.json({ deleted:true, key:req.params.key });
});

// ── COLLECTIONS ──────────────────────────────────

app.get('/collections', auth, (req, res) => {
  const db = readDB();
  const colls = Object.values(db.collections||{})
    .filter(c => c.userId === req.tk.userId)
    .map(c => ({ ...c, count: (db.records[`${c.userId}:${c.name}`]||[]).length }));
  res.json({ collections: colls });
});

app.delete('/collections/:name', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.name}`;
  if (!db.collections[key]) return res.status(404).json({ error:'Coleção não encontrada' });
  delete db.collections[key];
  delete db.records[key];
  writeDB(db);
  res.json({ deleted:true, collection:req.params.name });
});

// ── API CRUD ─────────────────────────────────────

app.get('/api/:coll', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.coll}`;
  let recs  = db.records[key] || [];
  const { _limit, _offset, token, ...filters } = req.query;
  Object.entries(filters).forEach(([k,v]) => { recs = recs.filter(r => String(r[k]??'') === String(v)); });
  const offset = parseInt(_offset)||0;
  const limit  = parseInt(_limit)||recs.length;
  res.json({ data: recs.slice(offset, offset+limit), count: recs.length, collection: req.params.coll });
});

app.get('/api/:coll/:id', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.coll}`;
  const rec = (db.records[key]||[]).find(r => r._id === req.params.id);
  if (!rec) return res.status(404).json({ error:'Registo não encontrado', status:404 });
  res.json(rec);
});

app.post('/api/:coll', auth, (req, res) => {
  const db      = readDB();
  const userId  = req.tk.userId;
  const key     = `${userId}:${req.params.coll}`;
  if (!db.collections[key])
    db.collections[key] = { name:req.params.coll, userId, created:Date.now() };
  if (!db.records[key]) db.records[key] = [];
  const rec = { _id:uid(), _created:Date.now(), ...req.body };
  db.records[key].push(rec);
  writeDB(db);
  res.status(201).json(rec);
});

app.put('/api/:coll/:id', auth, (req, res) => {
  const db   = readDB();
  const key  = `${req.tk.userId}:${req.params.coll}`;
  const recs = db.records[key]||[];
  const idx  = recs.findIndex(r => r._id === req.params.id);
  if (idx===-1) return res.status(404).json({ error:'Registo não encontrado', status:404 });
  recs[idx] = { _id:req.params.id, _created:recs[idx]._created, _updated:Date.now(), ...req.body };
  db.records[key] = recs;
  writeDB(db);
  res.json(recs[idx]);
});

app.patch('/api/:coll/:id', auth, (req, res) => {
  const db   = readDB();
  const key  = `${req.tk.userId}:${req.params.coll}`;
  const recs = db.records[key]||[];
  const idx  = recs.findIndex(r => r._id === req.params.id);
  if (idx===-1) return res.status(404).json({ error:'Registo não encontrado', status:404 });
  recs[idx] = { ...recs[idx], ...req.body, _updated:Date.now() };
  db.records[key] = recs;
  writeDB(db);
  res.json(recs[idx]);
});

app.delete('/api/:coll/:id', auth, (req, res) => {
  const db      = readDB();
  const key     = `${req.tk.userId}:${req.params.coll}`;
  const before  = db.records[key]||[];
  const after   = before.filter(r => r._id !== req.params.id);
  if (after.length === before.length)
    return res.status(404).json({ error:'Registo não encontrado', status:404 });
  db.records[key] = after;
  writeDB(db);
  res.json({ deleted:true, id:req.params.id, collection:req.params.coll });
});

// ── Start ────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🟢 Apply API a correr em http://localhost:${PORT}\n`);
});
