// routes/sites.js
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { spawn, execSync } = require('child_process');
const { spawnSync } = require('child_process');

const NGINX_DIR = '/etc/nginx/sites-available';
const NGINX_ENABLED = '/etc/nginx/sites-enabled';

function runPromise(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || stdout || err.message));
      resolve({ stdout, stderr });
    });
  });
}

// add domain - creates folder, creates nginx conf and inserts into domains table
router.post('/add', async (req, res) => {
  if (!req.session.user) return res.status(403).send('forbidden');
  const username = req.session.user.username;
  const domain = req.body.domain;
  if (!domain) return res.status(400).send('missing domain');

  try {
    const userHome = `/home/${username}/www/${domain}`;
    await runPromise(`sudo mkdir -p ${userHome}`);
    await runPromise(`sudo chown -R ${username}:${username} /home/${username}/www`);

    // Определяем доступную версию PHP
    let phpVersion = '8.2'; // версия по умолчанию
    try {
      // Проверяем, какие версии PHP-FPM установлены и активны
      const result = await runPromise('sudo systemctl list-units --type=service --state=active | grep php | grep fpm | head -1');
      const match = result.match(/php(\d+\.\d+)-fpm/);
      if (match) {
        phpVersion = match[1];
      }
    } catch (e) {
      console.log('Не удалось определить версию PHP, используем по умолчанию 8.2');
    }

    const confPath = path.join(NGINX_DIR, domain);
    const conf = `server {
    listen 80;
    server_name ${domain};
    root ${userHome};
    index index.php index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${phpVersion}-fpm-${username}.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\\.ht {
        deny all;
    }
}`;

    fs.writeFileSync(`/tmp/${domain}.conf`, conf);
    await runPromise(`sudo mv /tmp/${domain}.conf ${confPath}`);
    await runPromise(`sudo ln -sf ${confPath} ${NGINX_ENABLED}/${domain}`);
    await runPromise(`sudo cp /var/www/html/index.html /home/${username}/www/${domain}/index.html`);
    
    // Создаем PHP-FPM пул для пользователя, если его нет
// Создаем PHP-FPM пул для пользователя, если его нет
try {
  const poolConfig = `[${username}]
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
php_admin_value[memory_limit] = 128M
php_admin_value[disable_functions] = exec,passthru,shell_exec,system
php_admin_value[open_basedir] = /home/${username}/www/:/tmp/`;

  fs.writeFileSync(`/tmp/${username}.conf`, poolConfig);
  await runPromise(`sudo mv /tmp/${username}.conf /etc/php/${phpVersion}/fpm/pool.d/${username}.conf`);
  
  // Создаем директорию для сокетов если не существует
  await runPromise(`sudo mkdir -p /run/php`);
  
  // Перезапускаем PHP-FPM
  await runPromise(`sudo systemctl restart php${phpVersion}-fpm`);
  
  // Проверяем, что сокет создался и имеет правильные права
  await new Promise(resolve => setTimeout(resolve, 1000)); // Ждем секунду
  await runPromise(`sudo ls -la /run/php/ | grep ${username}`);
  
} catch (e) {
  console.log('Не удалось создать PHP-FPM пул, возможно он уже существует:', e.message);
}

    await runPromise('sudo nginx -t');
    await runPromise('sudo systemctl reload nginx');

    await req.pool.query('INSERT INTO domains (domain, owner_username, nginx_conf_path) VALUES (?, ?, ?)', [domain, username, confPath]);
    res.redirect('/dashboard');
  } catch (e) {
    console.error(e);
    res.status(500).send('Ошибка при добавлении домена: ' + e.message);
  }
});

// issue cert - returns a streaming endpoint for logs via SSE
router.get('/:domain/cert', async (req, res) => {
  if (!req.session.user) return res.status(403).send('forbidden');
  const domain = req.params.domain;
  
  // permission: only owner or admin
  const [[d]] = await req.pool.query('SELECT * FROM domains WHERE domain = ?', [domain]);
  if (!d) return res.status(404).send('domain not found');
  if (d.owner_username !== req.session.user.username && req.session.user.role !== 'admin') {
    return res.status(403).send('forbidden');
  }

  // SSE setup
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });
  res.flushHeaders?.();

  // Отправляем начальное сообщение
  res.write(`data: Начинаем процесс выпуска сертификата для ${domain}\n\n`);
  
  try {
    // Читаем конфигурационный файл домена
    const configPath = `/etc/nginx/sites-available/${domain}`;
    const configContent = await fs.promises.readFile(configPath, 'utf8');
    
    // Извлекаем все домены из server_name
    const serverNameMatch = configContent.match(/server_name\s+([^;]+);/);
    if (!serverNameMatch) {
      res.write('data: Ошибка: не удалось найти server_name в конфигурации\n\n');
      return res.end();
    }
    
    const serverNames = serverNameMatch[1].trim().split(/\s+/);
    res.write(`data: Найдены домены: ${serverNames.join(', ')}\n\n`);
    
    // Формируем аргументы для certbot с всеми доменами
    const certbotArgs = [
      'certbot', '--nginx',
      '--non-interactive',
      '--agree-tos',
      '--email', 'sas@rollyk.ru'
    ];
    
    // Добавляем все домены как параметры -d
    serverNames.forEach(domainName => {
      certbotArgs.push('-d', domainName);
    });
    
    res.write(`data: Выполняем команду: sudo ${certbotArgs.join(' ')}\n\n`);
    
    const child = spawn('sudo', certbotArgs);
    
    child.stdout.on('data', (data) => {
      const lines = data.toString().split('\n');
      lines.forEach(line => {
        if (line.trim()) {
          res.write(`data: ${line}\n\n`);
        }
      });
    });
    
    child.stderr.on('data', (data) => {
      const lines = data.toString().split('\n');
      lines.forEach(line => {
        if (line.trim()) {
          res.write(`data: [ERROR] ${line}\n\n`);
        }
      });
    });

    child.on('close', (code) => {
        if (code === 0) {
            res.write('event: end\n');
            res.write('data: Процесс успешно завершен!\n\n');

            req.pool.query('UPDATE domains SET ssl_status = "active" WHERE domain = ?', [domain])
                .catch(err => console.error('Ошибка при обновлении статуса SSL:', err));
        } else {
            res.write('event: end\n');
            res.write(`data: Процесс завершен с кодом ошибки: ${code}\n\n`);
        }
        res.end();
    });
    
    child.on('error', (error) => {
      res.write(`data: Ошибка выполнения команды: ${error.message}\n\n`);
      res.end();
    });
    
    // Обработка закрытия соединения клиентом
    req.on('close', () => {
      if (!child.killed) {
        child.kill(); // Прерываем процесс, если клиент отключился
      }
    });
    
  } catch (error) {
    res.write(`data: Неожиданная ошибка: ${error.message}\n\n`);
    res.end();
  }
});

// get/edit nginx config
router.get('/edit/:domain', async (req, res) => {
  const domain = req.params.domain;
  const [[d]] = await req.pool.query('SELECT * FROM domains WHERE domain = ?', [domain]);
  if (!d) return res.status(404).send('domain not found');
  if (d.owner_username !== req.session.user.username && req.session.user.role !== 'admin') return res.status(403).send('forbidden');
  const conf = fs.readFileSync(d.nginx_conf_path, 'utf-8');
  res.render('edit_conf', { user: req.session.user, domain, conf });
});

router.post('/edit/:domain', async (req, res) => {
  const domain = req.params.domain;
  const content = req.body.config;
  const [[d]] = await req.pool.query('SELECT * FROM domains WHERE domain = ?', [domain]);
  if (!d) return res.status(404).send('domain not found');
  if (d.owner_username !== req.session.user.username && req.session.user.role !== 'admin') return res.status(403).send('forbidden');

  fs.writeFileSync(`/tmp/${domain}.conf`, content);
  try {
    await runPromise(`sudo mv /tmp/${domain}.conf ${d.nginx_conf_path}`);
    await runPromise('sudo nginx -t');
    await runPromise('sudo systemctl reload nginx');
    res.redirect('/dashboard');
  } catch (e) {
    // keep old file if test failed
    res.status(400).send('nginx test failed: ' + e.message);
  }
});

router.post('/delete/:domain', async (req, res) => {
  const domain = req.params.domain;
  const username = req.session.user.username;

  // Проверка владельца домена
  const [[domainData]] = await req.pool.query(
    'SELECT owner_username FROM domains WHERE domain = ?',
    [domain]
  );
  if (!domainData) return res.status(404).send('Домен не найден');
  if (domainData.owner_username !== username && req.session.user.role !== 'admin')
    return res.status(403).send('Нет доступа');

  try {
    // Удаляем nginx конфиги
      spawnSync('sudo', ['rm', `/etc/nginx/sites-available/${domain}`]);
      spawnSync('sudo', ['rm', `/etc/nginx/sites-enabled/${domain}`]);

    // Удаляем папку сайта
    const sitePath = `/home/${username}/www/${domain}`;
    if (fs.existsSync(sitePath)) fs.rmSync(sitePath, { recursive: true, force: true });

    // Удаляем запись из БД
    await req.pool.query('DELETE FROM domains WHERE domain = ?', [domain]);

    // Тест nginx
    const test = spawnSync('sudo', ['nginx', '-t'], { encoding: 'utf8' });
    console.log(test.stdout);
    console.log(test.stderr);

    if (test.status === 0) {
        // reload только если тест успешен
        const reload = spawnSync('sudo', ['systemctl', 'reload', 'nginx'], { encoding: 'utf8' });
        console.log(reload.stdout);
        console.log(reload.stderr);
    } else {
        console.error('Ошибка в конфигурации nginx, reload не выполняем');

    }
    res.redirect('/dashboard');
  } catch (e) {
    console.error(e);
    res.status(500).send('Ошибка при удалении домена');
  }
});

module.exports = router;
