// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const expressLayouts = require('express-ejs-layouts');
const flash = require('connect-flash');
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const app = express();

// --- CONFIG: from .env (edit .env in project root) ---
const PANEL_DB = process.env.MYSQL_DB || 'panel_db';
const MYSQL_USER = process.env.MYSQL_USER || 'rollyk';
const MYSQL_PASS = process.env.MYSQL_PASS || '';
const MYSQL_HOST = process.env.MYSQL_HOST || 'localhost';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const PORT = process.env.PORT || 3000;
// ----------------------------------------------

// MySQL pool (panel_db)
const pool = mysql.createPool({
  host: MYSQL_HOST,
  user: MYSQL_USER,
  password: MYSQL_PASS,
  database: PANEL_DB,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// make pool available via req.pool
app.use((req, res, next) => { req.pool = pool; next(); });

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false }));
app.use(flash());

// simple auth middleware using system password check (sudo -S -u username whoami)
const { exec } = require('child_process');

async function fetchRole(username) {
  const [rows] = await pool.query('SELECT role FROM users WHERE username = ?', [username]);
  if (!rows.length) return null;
  return rows[0].role;
}

app.use(expressLayouts);
app.set('layout', 'layout');

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const role = await fetchRole(username);
  if (!role) return res.render('index', { error: 'Пользователь не зарегистрирован в панели' });

  // check system password by trying a harmless sudo -S command
  // NOTE: be careful with passing passwords into shell; this is a simple approach for a private/non-prod setup
  exec(`echo ${escapeShell(password)} | sudo -S -u ${escapeShell(username)} whoami`, (err, stdout) => {
    if (err) return res.render('index', { error: 'Неверный логин/пароль' });
    req.session.user = { username, role };
    res.redirect('/dashboard');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('Доступ запрещён');
  next();
}

// routes
const usersRouter = require('./routes/users');
const sitesRouter = require('./routes/sites');
const dbRouter = require('./routes/db');

app.use('/users', usersRouter);
app.use('/sites', sitesRouter);
app.use('/databases', dbRouter);

app.get('/', (req, res) => {
  res.render('index', { error: req.flash('error') });
});

app.get('/dashboard', requireAuth, async (req, res) => {
  // basic dashboard
  const username = req.session.user.username;
  const role = req.session.user.role;
  // fetch domains owned by user (or all for admin)
  const q = role === 'admin' ? 'SELECT * FROM domains' : 'SELECT * FROM domains WHERE owner_username = ?';
  const params = role === 'admin' ? [] : [username];
  const [domains] = await pool.query(q, params);
  res.render('dashboard', { user: req.session.user, domains });
});

app.listen(PORT, () => console.log(`Mini hosting panel running on http://localhost:${PORT}`));

// helper: naive shell escape for simple cases (do not use for complex input without better sanitization)
function escapeShell(s) {
  return String(s).replace(/([\\\\"'`$])/g, '\\$1');
}
