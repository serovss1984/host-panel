// routes/db.js
const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

function runPromise(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || stdout || err.message));
      resolve({ stdout, stderr });
    });
  });
}

// create database (owner creates their db prefixed)
router.post('/create', async (req, res) => {
  if (!req.session.user) return res.status(403).send('forbidden');
  const owner = req.session.user.username;
  const name = req.body.name;
  if (!name) return res.status(400).send('missing name');
  const dbName = `${owner}_${name}`;

  try {
    // Create DB as root (assumes mysql root has no password or rollyk can run mysql -u root)
    await runPromise(`mysql -u root -e "CREATE DATABASE '${dbName}';"`);
    // create mysql user and grant to databases with prefix owner_*
    // Here we GRANT ALL on databases that begin with owner_ to the user
    await runPromise(`mysql -u root -e "CREATE USER IF NOT EXISTS '${owner}'@'localhost' IDENTIFIED BY '${'SYSTEM_PASSWORD_NOT_HANDLED'}'; GRANT ALL PRIVILEGES ON \`${owner}_%\`.* TO '${owner}'@'localhost'; FLUSH PRIVILEGES;"`);

    await req.pool.query('INSERT INTO databases (db_name, owner_username) VALUES (?, ?)', [dbName, owner]);
    res.redirect('/dashboard');
  } catch (e) {
    res.status(500).send('Ошибка при создании БД: ' + e.message);
  }
});

// adminer redirect - create one-time token or proxy to adminer with auto-login
router.get('/adminer/:db', async (req, res) => {
  if (!req.session.user) return res.status(403).send('forbidden');
  const owner = req.session.user.username;
  const db = req.params.db; // expected owner_dbname or check ownership
  // for skeleton: redirect to adminer page with query params (NOT secure) - implement server-side proxy for production
  res.redirect(`/adminer/?username=${owner}&db=${db}`);
});

module.exports = router;
