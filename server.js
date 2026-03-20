const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');

const app      = express();
const PORT     = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE  = path.join(DATA_DIR, 'db.json');

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ── DB ──────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users:{}, tokens:{}, collections:{}, records:{}, files:{} }; }
}
function writeDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db)); }
function uid()   { return 'rec_' + crypto.randomBytes(8).toString('hex'); }
function fid()   { return 'file_' + crypto.randomBytes(8).toString('hex'); }
function genTk() { return 'apl_' + crypto.randomBytes(24).toString('hex'); }
function hash(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// ── Auth ─────────────────────────────────────────
function auth(req, res, next) {
  const raw   = (req.headers.authorization||'').replace(/^Bearer /i,'').trim();
  const token = raw || req.query.token || req.query.t || '';
  if (!token) return res.status(401).json({ error:'Token obrigatório', status:401 });
  const db = readDB();
  const tk = db.tokens[token];
  if (!tk) return res.status(401).json({ error:'Token inválido', status:401 });
  tk.lastUsed = Date.now();
  db.tokens[token] = tk;
  writeDB(db);
  req.tk = tk;
  next();
}

// ── Frontend ──────────────────────────────────────
app.get('/', (req, res) => {
  const f = path.join(__dirname, 'apply.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.json({ service:'Apply API', version:'2.0', status:'running' });
});
app.get('/ping', (req, res) => res.json({ status:'ok', time: Date.now() }));

// ── Auth endpoints ────────────────────────────────
app.post('/auth/register', (req, res) => {
  const { email, password, name } = req.body||{};
  if (!email||!password) return res.status(400).json({ error:'Email e password obrigatórios' });
  if (password.length < 6) return res.status(400).json({ error:'Password: mínimo 6 caracteres' });
  const db = readDB();
  if (!db.users)  db.users  = {};
  if (!db.tokens) db.tokens = {};
  if (db.users[email]) return res.status(409).json({ error:'Email já registado' });
  const userId = uid();
  db.users[email] = { id:userId, email, name:name||email.split('@')[0], hash:hash(email+':'+password), created:Date.now() };
  const key = genTk();
  db.tokens[key] = { key, name:'Token Principal', userId, email, perms:'rw', created:Date.now() };
  writeDB(db);
  res.status(201).json({ token:key, user:{ email, name:db.users[email].name } });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body||{};
  const db = readDB();
  const user = (db.users||{})[email];
  if (!user || user.hash !== hash(email+':'+password))
    return res.status(401).json({ error:'Email ou password incorretos' });
  const tokens = Object.values(db.tokens||{}).filter(t=>t.userId===user.id);
  res.json({ token: tokens[0]?.key||'', tokens, user:{ email, name:user.name } });
});

app.post('/auth/check', (req, res) => {
  const raw = (req.headers.authorization||'').replace(/^Bearer /i,'').trim();
  const db  = readDB();
  const tk  = (db.tokens||{})[raw];
  if (!tk) return res.status(401).json({ valid:false });
  res.json({ valid:true, user:{ email:tk.email }, token:tk.key });
});

// ── Tokens ────────────────────────────────────────
app.get('/tokens', auth, (req, res) => {
  const db = readDB();
  res.json({ tokens: Object.values(db.tokens||{}).filter(t=>t.userId===req.tk.userId) });
});

app.post('/tokens', auth, (req, res) => {
  const { name, perms } = req.body||{};
  if (!name) return res.status(400).json({ error:'Nome obrigatório' });
  const db = readDB();
  const key = genTk();
  db.tokens[key] = { key, name, userId:req.tk.userId, email:req.tk.email, perms:perms||'rw', created:Date.now() };
  writeDB(db);
  res.status(201).json(db.tokens[key]);
});

app.delete('/tokens/:key', auth, (req, res) => {
  const db = readDB();
  const tk = (db.tokens||{})[req.params.key];
  if (!tk||tk.userId!==req.tk.userId) return res.status(404).json({ error:'Token não encontrado' });
  // Não apagar o próprio token atual
  if (req.params.key === req.tk.key) return res.status(400).json({ error:'Não podes revogar o token atual' });
  delete db.tokens[req.params.key];
  writeDB(db);
  res.json({ deleted:true });
});

// ── Collections ───────────────────────────────────
app.get('/collections', auth, (req, res) => {
  const db = readDB();
  const colls = Object.values(db.collections||{})
    .filter(c=>c.userId===req.tk.userId)
    .map(c=>({ ...c, count:(db.records||{})[`${c.userId}:${c.name}`]?.length||0 }));
  res.json({ collections:colls });
});

app.post('/collections', auth, (req, res) => {
  const { name, desc } = req.body||{};
  if (!name||!/^[a-z0-9_]+$/.test(name)) return res.status(400).json({ error:'Nome inválido (só minúsculas, números e _)' });
  const db  = readDB();
  const key = `${req.tk.userId}:${name}`;
  if ((db.collections||{})[key]) return res.status(409).json({ error:'Coleção já existe' });
  if (!db.collections) db.collections = {};
  if (!db.records)     db.records     = {};
  db.collections[key] = { name, desc:desc||'', userId:req.tk.userId, created:Date.now() };
  db.records[key]     = [];
  writeDB(db);
  res.status(201).json(db.collections[key]);
});

app.delete('/collections/:name', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.name}`;
  if (!(db.collections||{})[key]) return res.status(404).json({ error:'Coleção não encontrada' });
  delete db.collections[key];
  delete (db.records||{})[key];
  writeDB(db);
  res.json({ deleted:true });
});

// ── Files / Images ────────────────────────────────
app.post('/files', auth, (req, res) => {
  const { name, type, data, collection } = req.body||{};
  if (!data) return res.status(400).json({ error:'Dados do ficheiro obrigatórios (base64)' });
  const db = readDB();
  if (!db.files) db.files = {};
  const id  = fid();
  const ext = (name||'file').split('.').pop().toLowerCase();
  db.files[id] = { id, name:name||'ficheiro', type:type||'application/octet-stream', ext, data, userId:req.tk.userId, collection:collection||null, created:Date.now(), size: Math.round(data.length*0.75) };
  writeDB(db);
  res.status(201).json({ id, name:db.files[id].name, type:db.files[id].type, url:`${req.protocol}://${req.get('host')}/files/${id}`, size:db.files[id].size });
});

app.get('/files', auth, (req, res) => {
  const db = readDB();
  const files = Object.values(db.files||{})
    .filter(f=>f.userId===req.tk.userId)
    .map(({data,...f})=>({ ...f, url:`${req.protocol}://${req.get('host')}/files/${f.id}` }));
  res.json({ files });
});

app.get('/files/:id', (req, res) => {
  const db  = readDB();
  const raw = (req.headers.authorization||'').replace(/^Bearer /i,'').trim() || req.query.token||'';
  const f   = (db.files||{})[req.params.id];
  if (!f) return res.status(404).json({ error:'Ficheiro não encontrado' });
  // Ficheiros públicos se tiver token válido ou se for imagem
  const buf = Buffer.from(f.data.replace(/^data:[^;]+;base64,/,''), 'base64');
  res.set('Content-Type', f.type);
  res.set('Content-Disposition', `inline; filename="${f.name}"`);
  res.send(buf);
});

app.delete('/files/:id', auth, (req, res) => {
  const db = readDB();
  const f  = (db.files||{})[req.params.id];
  if (!f||f.userId!==req.tk.userId) return res.status(404).json({ error:'Ficheiro não encontrado' });
  delete db.files[req.params.id];
  writeDB(db);
  res.json({ deleted:true });
});

// ── API CRUD ──────────────────────────────────────
app.get('/api/:coll', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.coll}`;
  // Auto-cria coleção se não existir
  if (!(db.collections||{})[key]) {
    if (!db.collections) db.collections = {};
    if (!db.records)     db.records     = {};
    db.collections[key] = { name:req.params.coll, userId:req.tk.userId, created:Date.now() };
    db.records[key]     = [];
    writeDB(db);
  }
  let recs = (db.records||{})[key]||[];
  const { _limit, _offset, _sort, _order, token, t, ...filters } = req.query;
  // Filtros
  Object.entries(filters).forEach(([k,v]) => { recs = recs.filter(r=>String(r[k]??'')===String(v)); });
  // Sort
  if (_sort) { const o=_order==='desc'?-1:1; recs=[...recs].sort((a,b)=>(a[_sort]>b[_sort]?o:-o)); }
  const total  = recs.length;
  const offset = parseInt(_offset)||0;
  const limit  = Math.min(parseInt(_limit)||1000, 1000);
  res.json({ data:recs.slice(offset,offset+limit), count:recs.length, total, collection:req.params.coll, offset, limit });
});

app.get('/api/:coll/:id', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.coll}`;
  const rec = ((db.records||{})[key]||[]).find(r=>r._id===req.params.id);
  if (!rec) return res.status(404).json({ error:'Registo não encontrado' });
  res.json(rec);
});

app.post('/api/:coll', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.coll}`;
  if (!db.collections) db.collections = {};
  if (!db.records)     db.records     = {};
  if (!db.collections[key]) db.collections[key] = { name:req.params.coll, userId:req.tk.userId, created:Date.now() };
  if (!db.records[key])     db.records[key]     = [];
  const rec = { _id:uid(), _created:Date.now(), _updated:Date.now(), ...req.body };
  db.records[key].push(rec);
  writeDB(db);
  res.status(201).json(rec);
});

app.post('/api/:coll/bulk', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.coll}`;
  const items = Array.isArray(req.body) ? req.body : req.body.data||[];
  if (!items.length) return res.status(400).json({ error:'Array de dados obrigatório' });
  if (!db.collections) db.collections = {};
  if (!db.records)     db.records     = {};
  if (!db.collections[key]) db.collections[key] = { name:req.params.coll, userId:req.tk.userId, created:Date.now() };
  if (!db.records[key])     db.records[key]     = [];
  const recs = items.map(d=>({ _id:uid(), _created:Date.now(), _updated:Date.now(), ...d }));
  db.records[key].push(...recs);
  writeDB(db);
  res.status(201).json({ inserted:recs.length, data:recs });
});

app.put('/api/:coll/:id', auth, (req, res) => {
  const db   = readDB();
  const key  = `${req.tk.userId}:${req.params.coll}`;
  const recs = (db.records||{})[key]||[];
  const idx  = recs.findIndex(r=>r._id===req.params.id);
  if (idx===-1) return res.status(404).json({ error:'Registo não encontrado' });
  recs[idx] = { _id:req.params.id, _created:recs[idx]._created, _updated:Date.now(), ...req.body };
  db.records[key] = recs; writeDB(db);
  res.json(recs[idx]);
});

app.patch('/api/:coll/:id', auth, (req, res) => {
  const db   = readDB();
  const key  = `${req.tk.userId}:${req.params.coll}`;
  const recs = (db.records||{})[key]||[];
  const idx  = recs.findIndex(r=>r._id===req.params.id);
  if (idx===-1) return res.status(404).json({ error:'Registo não encontrado' });
  recs[idx] = { ...recs[idx], ...req.body, _updated:Date.now() };
  db.records[key] = recs; writeDB(db);
  res.json(recs[idx]);
});

app.delete('/api/:coll/:id', auth, (req, res) => {
  const db     = readDB();
  const key    = `${req.tk.userId}:${req.params.coll}`;
  const before = (db.records||{})[key]||[];
  const after  = before.filter(r=>r._id!==req.params.id);
  if (after.length===before.length) return res.status(404).json({ error:'Registo não encontrado' });
  db.records[key] = after; writeDB(db);
  res.json({ deleted:true, id:req.params.id });
});

// Apagar todos os registos de uma coleção
app.delete('/api/:coll', auth, (req, res) => {
  const db  = readDB();
  const key = `${req.tk.userId}:${req.params.coll}`;
  if (!(db.records||{})[key]) return res.status(404).json({ error:'Coleção não encontrada' });
  const count = db.records[key].length;
  db.records[key] = []; writeDB(db);
  res.json({ deleted:count, collection:req.params.coll });
});

app.listen(PORT, () => console.log(`\n🟢 Apply API v2.0 → http://localhost:${PORT}\n`));
