const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_PASSWORD = process.env.APP_PASSWORD;
if (!APP_PASSWORD) { console.error('ERROR: APP_PASSWORD no definida'); process.exit(1); }

const DATA_DIR = '/data/files';
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'sesion-secreta-gestor',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 }
}));

// Encryption helpers
function deriveKey(password) {
  return crypto.scryptSync(password, 'gestor-salt-v1', 32);
}

function encrypt(text, password) {
  const key = deriveKey(password);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(data, password) {
  const [ivHex, encHex] = data.split(':');
  const key = deriveKey(password);
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]).toString('utf8');
}

function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  res.status(401).json({ error: 'No autenticado' });
}

// ── Login page ──────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  if (req.session.authenticated) return res.redirect('/app');
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gestor de Contraseñas</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0d0d;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#161616;border:1px solid #252525;border-radius:20px;padding:52px 44px;width:100%;max-width:380px;text-align:center}
.lock{font-size:52px;margin-bottom:20px}
h1{color:#fff;font-size:22px;font-weight:700;margin-bottom:6px}
.sub{color:#555;font-size:14px;margin-bottom:36px}
input{width:100%;padding:14px 16px;background:#0d0d0d;border:1px solid #252525;border-radius:12px;color:#fff;font-size:16px;margin-bottom:14px;outline:none;transition:border-color .2s}
input:focus{border-color:#5b8def}
button{width:100%;padding:14px;background:#5b8def;color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:700;cursor:pointer;transition:background .2s}
button:hover{background:#4a7de0}
.err{color:#f87171;font-size:13px;margin-top:14px}
</style>
</head>
<body>
<div class="card">
  <div class="lock">🔐</div>
  <h1>Gestor de Contraseñas</h1>
  <p class="sub">Ingresa tu contraseña maestra</p>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Contraseña maestra" autofocus required/>
    <button type="submit">Entrar</button>
    ${req.query.error ? '<p class="err">Contraseña incorrecta</p>' : ''}
  </form>
</div>
</body>
</html>`);
});

app.post('/login', (req, res) => {
  if (req.body.password === APP_PASSWORD) {
    req.session.authenticated = true;
    req.session.password = req.body.password;
    res.redirect('/app');
  } else {
    res.redirect('/?error=1');
  }
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/'); });

// ── Main app ─────────────────────────────────────────────────────────────────
app.get('/app', (req, res) => {
  if (!req.session.authenticated) return res.redirect('/');
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gestor de Contraseñas</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0d0d;color:#e0e0e0;height:100vh;display:flex;flex-direction:column;overflow:hidden}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:#161616;border-bottom:1px solid #222;flex-shrink:0}
header h1{font-size:16px;font-weight:700;display:flex;align-items:center;gap:8px;color:#fff}
.logout-btn{padding:7px 14px;background:#1e1e1e;color:#888;border:1px solid #2a2a2a;border-radius:8px;font-size:13px;cursor:pointer;transition:all .2s}
.logout-btn:hover{color:#fff;border-color:#444}
.layout{display:flex;flex:1;overflow:hidden}
/* Sidebar */
.sidebar{width:240px;background:#111;border-right:1px solid #1e1e1e;display:flex;flex-direction:column;flex-shrink:0}
.sidebar-header{padding:16px;border-bottom:1px solid #1e1e1e;display:flex;align-items:center;justify-content:space-between}
.sidebar-title{font-size:12px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.8px}
.new-btn{width:28px;height:28px;background:#5b8def;color:#fff;border:none;border-radius:8px;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background .2s}
.new-btn:hover{background:#4a7de0}
.file-list{flex:1;overflow-y:auto;padding:8px}
.file-item{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;border-radius:10px;cursor:pointer;transition:background .15s;margin-bottom:2px;gap:8px}
.file-item:hover{background:#1a1a1a}
.file-item.active{background:#1c2a40;border:1px solid #2a4070}
.file-name{font-size:14px;color:#ccc;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.file-item.active .file-name{color:#fff}
.del-btn{opacity:0;background:none;border:none;color:#f87171;cursor:pointer;font-size:16px;padding:2px 4px;border-radius:4px;transition:opacity .2s}
.file-item:hover .del-btn{opacity:1}
.empty-msg{color:#444;font-size:13px;text-align:center;padding:32px 16px}
/* Editor */
.editor-area{flex:1;display:flex;flex-direction:column;overflow:hidden}
.editor-toolbar{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;background:#161616;border-bottom:1px solid #1e1e1e;gap:12px}
.file-title-input{background:none;border:none;color:#fff;font-size:16px;font-weight:600;flex:1;outline:none}
.file-title-input::placeholder{color:#444}
.save-btn{padding:8px 18px;background:#5b8def;color:#fff;border:none;border-radius:9px;font-size:14px;font-weight:700;cursor:pointer;transition:background .2s;white-space:nowrap}
.save-btn:hover{background:#4a7de0}
textarea{flex:1;width:100%;padding:24px;background:#0d0d0d;color:#d0d0d0;border:none;font-family:'Courier New',monospace;font-size:14px;line-height:1.8;resize:none;outline:none}
.placeholder-screen{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#333;gap:12px}
.placeholder-screen .icon{font-size:48px}
.placeholder-screen p{font-size:14px}
/* Toast */
.toast{position:fixed;bottom:24px;right:24px;background:#22c55e;color:#fff;padding:12px 20px;border-radius:10px;font-size:14px;font-weight:700;opacity:0;transform:translateY(8px);transition:all .25s;pointer-events:none}
.toast.show{opacity:1;transform:translateY(0)}
.toast.error{background:#f87171}
/* Modal */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);align-items:center;justify-content:center;z-index:100}
.modal-bg.open{display:flex}
.modal{background:#161616;border:1px solid #252525;border-radius:16px;padding:32px;width:100%;max-width:360px}
.modal h2{font-size:18px;margin-bottom:20px;color:#fff}
.modal input{width:100%;padding:12px 14px;background:#0d0d0d;border:1px solid #252525;border-radius:10px;color:#fff;font-size:15px;outline:none;margin-bottom:16px}
.modal input:focus{border-color:#5b8def}
.modal-btns{display:flex;gap:10px;justify-content:flex-end}
.modal-btns button{padding:9px 20px;border-radius:9px;font-size:14px;font-weight:600;cursor:pointer;border:none}
.btn-cancel{background:#1e1e1e;color:#888}
.btn-create{background:#5b8def;color:#fff}
</style>
</head>
<body>
<header>
  <h1>🔐 Gestor de Contraseñas</h1>
  <button class="logout-btn" onclick="location='/logout'">Cerrar sesión</button>
</header>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-header">
      <span class="sidebar-title">Archivos</span>
      <button class="new-btn" onclick="openModal()" title="Nuevo archivo">+</button>
    </div>
    <div class="file-list" id="fileList"></div>
  </aside>
  <div class="editor-area" id="editorArea">
    <div class="placeholder-screen" id="placeholder">
      <div class="icon">📄</div>
      <p>Selecciona un archivo o crea uno nuevo</p>
    </div>
  </div>
</div>

<!-- Modal nuevo archivo -->
<div class="modal-bg" id="modal">
  <div class="modal">
    <h2>Nuevo archivo</h2>
    <input type="text" id="newFileName" placeholder="Nombre del archivo" maxlength="60"/>
    <div class="modal-btns">
      <button class="btn-cancel" onclick="closeModal()">Cancelar</button>
      <button class="btn-create" onclick="createFile()">Crear</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let files = [];
let currentFile = null;

async function loadFiles() {
  const res = await fetch('/api/files');
  files = await res.json();
  renderList();
}

function renderList() {
  const list = document.getElementById('fileList');
  if (!files.length) {
    list.innerHTML = '<p class="empty-msg">Sin archivos. Crea uno con +</p>';
    return;
  }
  list.innerHTML = files.map(f => \`
    <div class="file-item \${currentFile === f ? 'active' : ''}" onclick="openFile('\${f}')">
      <span class="file-name">🔒 \${f}</span>
      <button class="del-btn" onclick="deleteFile(event,'\${f}')" title="Eliminar">✕</button>
    </div>
  \`).join('');
}

async function openFile(name) {
  const res = await fetch('/api/files/' + encodeURIComponent(name));
  const data = await res.json();
  currentFile = name;
  renderList();
  document.getElementById('placeholder').style.display = 'none';
  const area = document.getElementById('editorArea');
  area.innerHTML = \`
    <div class="editor-toolbar">
      <input class="file-title-input" value="\${name}" readonly/>
      <button class="save-btn" onclick="save()">Guardar</button>
    </div>
    <textarea id="editor" spellcheck="false">\${data.content}</textarea>
  \`;
}

async function save() {
  const content = document.getElementById('editor').value;
  const res = await fetch('/api/files/' + encodeURIComponent(currentFile), {
    method: 'PUT',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ content })
  });
  showToast(res.ok ? 'Guardado' : 'Error al guardar', !res.ok);
}

function openModal() {
  document.getElementById('modal').classList.add('open');
  setTimeout(() => document.getElementById('newFileName').focus(), 50);
}
function closeModal() {
  document.getElementById('modal').classList.remove('open');
  document.getElementById('newFileName').value = '';
}

async function createFile() {
  const name = document.getElementById('newFileName').value.trim();
  if (!name) return;
  const res = await fetch('/api/files', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ name, content: '' })
  });
  if (res.ok) {
    closeModal();
    await loadFiles();
    openFile(name);
  } else {
    const d = await res.json();
    showToast(d.error || 'Error', true);
  }
}

async function deleteFile(e, name) {
  e.stopPropagation();
  if (!confirm(\`¿Eliminar "\${name}"?\`)) return;
  await fetch('/api/files/' + encodeURIComponent(name), { method: 'DELETE' });
  if (currentFile === name) {
    currentFile = null;
    document.getElementById('editorArea').innerHTML = '<div class="placeholder-screen" id="placeholder"><div class="icon">📄</div><p>Selecciona un archivo o crea uno nuevo</p></div>';
  }
  await loadFiles();
}

function showToast(msg, isError = false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (isError ? ' error' : '');
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}

// Ctrl+S
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's' && currentFile) { e.preventDefault(); save(); }
});
// Enter en modal
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.getElementById('modal').classList.contains('open')) createFile();
  if (e.key === 'Escape') closeModal();
});

loadFiles();
</script>
</body>
</html>`);
});

// ── API ───────────────────────────────────────────────────────────────────────
app.get('/api/files', requireAuth, (req, res) => {
  const files = fs.readdirSync(DATA_DIR)
    .filter(f => f.endsWith('.enc'))
    .map(f => f.replace('.enc', ''));
  res.json(files);
});

app.post('/api/files', requireAuth, (req, res) => {
  const { name, content } = req.body;
  if (!name || /[\/\\<>:"|?*]/.test(name)) return res.status(400).json({ error: 'Nombre inválido' });
  const file = path.join(DATA_DIR, name + '.enc');
  if (fs.existsSync(file)) return res.status(400).json({ error: 'Ya existe un archivo con ese nombre' });
  fs.writeFileSync(file, encrypt(content || '', req.session.password));
  res.json({ ok: true });
});

app.get('/api/files/:name', requireAuth, (req, res) => {
  const file = path.join(DATA_DIR, req.params.name + '.enc');
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'No encontrado' });
  try {
    const content = decrypt(fs.readFileSync(file, 'utf8'), req.session.password);
    res.json({ content });
  } catch {
    res.status(500).json({ error: 'Error al desencriptar' });
  }
});

app.put('/api/files/:name', requireAuth, (req, res) => {
  const file = path.join(DATA_DIR, req.params.name + '.enc');
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'No encontrado' });
  fs.writeFileSync(file, encrypt(req.body.content || '', req.session.password));
  res.json({ ok: true });
});

app.delete('/api/files/:name', requireAuth, (req, res) => {
  const file = path.join(DATA_DIR, req.params.name + '.enc');
  if (fs.existsSync(file)) fs.unlinkSync(file);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Gestor corriendo en puerto ${PORT}`));
