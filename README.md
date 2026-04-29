# Mini Hosting Panel

This is a minimal skeleton for the "mini-hosting-panel" described in the convo.

**Important**: This skeleton focuses on structure and example flows. It is **not production-ready**. There are obvious security and robustness gaps (password handling, SQL injection prevention, proper escaping, secure Adminer proxying, safe deletion of databases, error handling, input validation, etc.) that you must implement before any public deployment.

## Quick setup

1. Install deps:

```bash
npm install
```

2. Create `panel_db` and required tables in MySQL, and grant `rollyk` proper rights. Example SQL (run as MySQL root):

```sql
CREATE DATABASE panel_db;
USE panel_db;
CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) UNIQUE, role ENUM('admin','user'));
CREATE TABLE domains (id INT AUTO_INCREMENT PRIMARY KEY, domain VARCHAR(255), owner_username VARCHAR(50), nginx_conf_path VARCHAR(255), ssl_status ENUM('none','pending','active') DEFAULT 'none', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE databases (id INT AUTO_INCREMENT PRIMARY KEY, db_name VARCHAR(255), owner_username VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

INSERT INTO users (username, role) VALUES ('rollyk', 'admin');
```

3. Edit `server.js` and set MySQL credentials for `rollyk`.

4. Run in development:

```bash
npm run dev
```

## Sudoers (example)

Add a restricted sudoers file for the Node process user (rollyk runs Node here) - careful with permissions!

```
# /etc/sudoers.d/mini-panel
rollyk ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/sbin/userdel, /bin/mkdir, /bin/chown, /usr/sbin/systemctl, /usr/bin/certbot, /bin/ln, /bin/rm, /usr/sbin/nginx
```

## Deleting users (HARD delete)

The `routes/users.js` contains a `POST /users/delete` route that:
- stops pm2 for the user
- removes php-fpm pool
- uninstall nginx site files
- deletes home directory `/home/username`
- removes DB records from `panel_db` and intends to drop MySQL DBs and user (implement carefully)

This is destructive: **use with caution**.

## Next steps / TODO (important):
- Securely handle system passwords (avoid echoing passwords into shell commands)
- Implement safe DB drop logic (list, confirm, drop per DB - no blind wildcard SQL)
- Implement Adminer proxy with server-side auto-login tokens (avoid sending raw passwords in URLs)
- Add input validation and escaping everywhere
- Improve logging and error handling
- Add HTTPS and admin IP whitelisting
# host-panel
