const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_PASSWORD = process.env.APP_PASSWORD;
if (!APP_PASSWORD) { console.error('ERROR: APP_PASSWORD no definida'); process.exit(1); }
const DATA_FILE = path.join('/data', 'claves.txt');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secreto-sesion-gestor',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 } // 8 horas
}));

// Ensure data directory exists
if (!fs.existsSync('/data')) fs.mkdirSync('/data', { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '');

function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  res.redirect('/');
}

// Login page
app.get('/', (req, res) => {
  if (req.session.authenticated) return res.redirect('/editor');
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gestor de Contraseñas</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f0f0f;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #1a1a1a;
      border: 1px solid #2a2a2a;
      border-radius: 16px;
      padding: 48px 40px;
      width: 100%;
      max-width: 380px;
      text-align: center;
    }
    .icon { font-size: 48px; margin-bottom: 16px; }
    h1 { color: #fff; font-size: 22px; margin-bottom: 8px; }
    p { color: #666; font-size: 14px; margin-bottom: 32px; }
    input {
      width: 100%;
      padding: 14px 16px;
      background: #111;
      border: 1px solid #2a2a2a;
      border-radius: 10px;
      color: #fff;
      font-size: 16px;
      margin-bottom: 16px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus { border-color: #4f8ef7; }
    button {
      width: 100%;
      padding: 14px;
      background: #4f8ef7;
      color: #fff;
      border: none;
      border-radius: 10px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: #3a7de8; }
    .error {
      color: #ff4f4f;
      font-size: 14px;
      margin-top: 16px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔐</div>
    <h1>Gestor de Contraseñas</h1>
    <p>Ingresa tu contraseña maestra para continuar</p>
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="Contraseña maestra" autofocus required />
      <button type="submit">Entrar</button>
      ${req.query.error ? '<p class="error">Contraseña incorrecta</p>' : ''}
    </form>
  </div>
</body>
</html>`);
});

// Login
app.post('/login', (req, res) => {
  if (req.body.password === APP_PASSWORD) {
    req.session.authenticated = true;
    res.redirect('/editor');
  } else {
    res.redirect('/?error=1');
  }
});

// Editor
app.get('/editor', requireAuth, (req, res) => {
  const content = fs.readFileSync(DATA_FILE, 'utf8');
  res.send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gestor de Contraseñas</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f0f0f;
      color: #fff;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 24px;
      background: #1a1a1a;
      border-bottom: 1px solid #2a2a2a;
    }
    header h1 { font-size: 18px; display: flex; align-items: center; gap: 8px; }
    .actions { display: flex; gap: 10px; }
    button {
      padding: 8px 18px;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    .btn-save { background: #4f8ef7; color: #fff; }
    .btn-save:hover { background: #3a7de8; }
    .btn-logout { background: #2a2a2a; color: #aaa; }
    .btn-logout:hover { background: #333; color: #fff; }
    textarea {
      flex: 1;
      width: 100%;
      padding: 24px;
      background: #0f0f0f;
      color: #e0e0e0;
      border: none;
      font-family: 'Courier New', monospace;
      font-size: 15px;
      line-height: 1.7;
      resize: none;
      outline: none;
    }
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #22c55e;
      color: #fff;
      padding: 12px 20px;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 600;
      opacity: 0;
      transition: opacity 0.3s;
    }
    .toast.show { opacity: 1; }
  </style>
</head>
<body>
  <header>
    <h1>🔐 Gestor de Contraseñas</h1>
    <div class="actions">
      <button class="btn-save" onclick="guardar()">Guardar</button>
      <a href="/logout"><button class="btn-logout">Cerrar sesión</button></a>
    </div>
  </header>
  <textarea id="editor" spellcheck="false">${content.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</textarea>
  <div class="toast" id="toast">Guardado correctamente</div>
  <script>
    async function guardar() {
      const content = document.getElementById('editor').value;
      const res = await fetch('/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
      if (res.ok) {
        const toast = document.getElementById('toast');
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2500);
      }
    }
    // Ctrl+S / Cmd+S to save
    document.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        guardar();
      }
    });
  </script>
</body>
</html>`);
});

// Save
app.post('/save', requireAuth, (req, res) => {
  fs.writeFileSync(DATA_FILE, req.body.content, 'utf8');
  res.json({ ok: true });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(PORT, () => console.log(`Gestor corriendo en puerto ${PORT}`));
