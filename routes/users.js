// routes/users.js
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');
const { spawn } = require('child_process');

function runPromise(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || stdout || err.message));
      resolve(stdout);
    });
  });
}

// Middleware для проверки админ прав
const requireAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Forbidden');
  }
};

// Получение списка системных пользователей
router.get('/system-users', requireAdmin, async (req, res) => {
  try {
    const result = await runPromise('sudo cut -d: -f1 /etc/passwd | grep -E "(^[a-z][a-z0-9_-]{2,30}$)" | sort');
    const users = result.split('\n').filter(user => user && ![
      'root', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 
      'news', 'uucp', 'proxy', 'www-data', 'backup', 'list', 'irc', 'gnats', 
      'nobody', 'systemd-network', 'systemd-resolve', 'systemd-timesync', 
      'messagebus', 'syslog', '_apt', 'tss', 'uuidd', 'tcpdump', 'avahi-autoipd', 
      'usbmux', 'rtkit', 'dnsmasq', 'cups-pk-helper', 'speech-dispatcher', 
      'avahi', 'kernoops', 'saned', 'nm-openvpn', 'hplip', 'whoopsie', 
      'colord', 'geoclue', 'pulse', 'gnome-initial-setup', 'gdm', 'mysql', 'ftp', 'sshd'
    ].includes(user));
    
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Смена пароля пользователем
router.post('/change-password', async (req, res) => {
  if (!req.session.user) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Укажите старый и новый пароль' });
  }

  try {
    const username = req.session.user.username;

    // Проверим старый пароль
    const check = spawn('su', ['-c', 'exit', username], {
      stdio: ['pipe', 'ignore', 'ignore']
    });

    check.stdin.write(oldPassword + '\n');
    check.stdin.end();

    check.on('close', (code) => {
      if (code !== 0) {
        return res.status(401).json({ error: 'Неверный текущий пароль' });
      }

      // Меняем пароль
      const chpasswd = spawn('sudo', ['chpasswd']);
      chpasswd.stdin.write(`${username}:${newPassword}\n`);
      chpasswd.stdin.end();

      chpasswd.on('close', (c) => {
        if (c === 0) {
          res.json({ success: true, message: 'Пароль успешно изменён' });
        } else {
          res.status(500).json({ error: 'Ошибка при смене пароля' });
        }
      });
    });
  } catch (err) {
    console.error('Ошибка при смене пароля:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Создание пользователя (обновленная версия)
router.post('/create', requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('missing username or password');

  try {
    // Проверяем, существует ли пользователь
    try {
      await runPromise(`id ${username}`);
      return res.status(400).send('User already exists');
    } catch (e) {
      // Пользователь не существует - продолжаем
    }

    // Создаем системного пользователя
    await runPromise(`sudo useradd -m -s /bin/bash ${username}`);
    await runPromise(`echo "${username}:${password}" | sudo chpasswd`);
    
    // Создаем директории
    await runPromise(`sudo mkdir -p /home/${username}/www /home/${username}/nodejs`);
    await runPromise(`sudo chown -R ${username}:${username} /home/${username}`);

    // Определяем версию PHP динамически
    let phpVersion = '8.2';
    try {
      const result = await runPromise('sudo systemctl list-units --type=service --state=active | grep php | grep fpm | head -1');
      const match = result.match(/php(\d+\.\d+)-fpm/);
      if (match) phpVersion = match[1];
    } catch (e) {
      console.log('Using default PHP version 8.2');
    }

    // Создаем php-fpm pool
    const poolConf = `[${username}]
user = ${username}
group = ${username}
listen = /run/php/php${phpVersion}-fpm-${username}.sock
listen.owner = ${username}
listen.group = ${username}
listen.mode = 0660
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
php_admin_value[upload_max_filesize] = 32M
php_admin_value[post_max_size] = 32M
php_admin_value[memory_limit] = 128M`;

    fs.writeFileSync(`/tmp/${username}.conf`, poolConf);
    await runPromise(`sudo mv /tmp/${username}.conf /etc/php/${phpVersion}/fpm/pool.d/${username}.conf`);
    await runPromise(`sudo systemctl reload php${phpVersion}-fpm`);

    // Создаем MySQL пользователя и базу данных
    const mysqlPassword = crypto.randomBytes(12).toString('hex');
    await runPromise(`sudo mysql -e "CREATE USER '${username}'@'localhost' IDENTIFIED BY '${mysqlPassword}';"`);
    await runPromise(`sudo mysql -e "CREATE DATABASE ${username};"`);
    await runPromise(`sudo mysql -e "GRANT ALL PRIVILEGES ON ${username}.* TO '${username}'@'localhost';"`);
    await runPromise(`sudo mysql -e "FLUSH PRIVILEGES;"`);

    // Сохраняем MySQL credentials
    const credentials = `MySQL username: ${username}
MySQL password: ${mysqlPassword}
MySQL database: ${username}`;
    
    fs.writeFileSync(`/tmp/mysql_${username}.txt`, credentials);
    await runPromise(`sudo mv /tmp/mysql_${username}.txt /home/${username}/mysql_credentials.txt`);
    await runPromise(`sudo chown ${username}:${username} /home/${username}/mysql_credentials.txt`);
    await runPromise(`sudo chmod 600 /home/${username}/mysql_credentials.txt`);

    // Устанавливаем Node.js (асинхронно, не блокируем ответ)
    setTimeout(async () => {
      try {
        const nvmInstall = `sudo -u ${username} bash -c '
          export NVM_DIR="/home/${username}/.nvm"
          [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" || {
            git clone https://github.com/nvm-sh/nvm.git "$NVM_DIR"
            . "$NVM_DIR/nvm.sh"
          }
          nvm install --lts
          npm install -g pm2
          pm2 startup systemd -u ${username} --hp /home/${username} || true
        '`;
        await runPromise(nvmInstall);
      } catch (e) {
        console.error('Error installing Node.js:', e);
      }
    }, 1000);

    // Добавляем в панель управления
    await req.pool.query('INSERT INTO users (username, role) VALUES (?, ?)', [username, 'user']);

    res.json({ 
      success: true, 
      message: 'User created successfully',
      mysqlPassword: mysqlPassword 
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка при создании пользователя: ' + e.message });
  }
});

// Удаление пользователя (обновленная версия)
router.delete('/delete/:username', requireAdmin, async (req, res) => {
  const { username } = req.params;
  
  try {
    // Проверяем, существует ли пользователь
    try {
      await runPromise(`id ${username}`);
    } catch (e) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Останавливаем PM2 процессы
    try {
      await runPromise(`sudo -u ${username} bash -c 'pm2 kill' || true`);
    } catch (e) {}

    // Удаляем MySQL пользователя и базы данных
    try {
      // Получаем все базы данных пользователя
      const dbsResult = await runPromise(`sudo mysql -e "SHOW DATABASES LIKE '${username}_%'"`);
      const databases = dbsResult.split('\n').filter(db => db && db !== 'Database');
      
      for (const db of databases) {
        await runPromise(`sudo mysql -e "DROP DATABASE IF EXISTS ${db}"`);
      }
      
      await runPromise(`sudo mysql -e "DROP USER IF EXISTS '${username}'@'localhost'"`);
    } catch (e) {
      console.error('Error cleaning MySQL:', e);
    }

    // Удаляем PHP-FPM pool
    try {
      let phpVersion = '8.2';
      const result = await runPromise('sudo systemctl list-units --type=service --state=active | grep php | grep fpm | head -1');
      const match = result.match(/php(\d+\.\d+)-fpm/);
      if (match) phpVersion = match[1];
      
      await runPromise(`sudo rm -f /etc/php/${phpVersion}/fpm/pool.d/${username}.conf`);
      await runPromise(`sudo systemctl reload php${phpVersion}-fpm`);
    } catch (e) {
      console.error('Error removing PHP-FPM pool:', e);
    }

    // Удаляем nginx конфиги
    const [rows] = await req.pool.query('SELECT domain, nginx_conf_path FROM domains WHERE owner_username = ?', [username]);
    for (const row of rows) {
      try {
        await runPromise(`sudo rm -f ${row.nginx_conf_path}`);
        await runPromise(`sudo rm -f /etc/nginx/sites-enabled/${row.domain}`);
      } catch (e) {}
    }
    await req.pool.query('DELETE FROM domains WHERE owner_username = ?', [username]);

    // Удаляем домашнюю директорию
    await runPromise(`sudo userdel -r ${username}`);

    // Удаляем из панели управления
    await req.pool.query('DELETE FROM users WHERE username = ?', [username]);

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка при удалении пользователя: ' + e.message });
  }
});

module.exports = router;
