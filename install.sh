#!/bin/bash
set -e

# ==============================================================================
# Anti-DDoS & Cloudflare Zero Trust Management Panel Auto-Installer
# Supported OS: Ubuntu 20.04/22.04/24.04, Debian 11/12
# ==============================================================================

echo "======================================================================"
echo " Starting Installation: Anti-DDoS & Cloudflare Management Panel"
echo "======================================================================"

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run this script as root (sudo bash install.sh)"
    exit 1
fi

# 1. Install Dependencies
echo "[*] Updating package list and installing prerequisites..."
apt-get update -y
apt-get install -y nginx php-fpm php-sqlite3 php-curl fail2ban nftables curl ufw

# 2. Detect PHP version and socket
PHP_VER=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
echo "[*] Detected PHP version: $PHP_VER"

# 3. Create Panel Directory
echo "[*] Setting up /opt/ddos-panel directory structure..."
mkdir -p /opt/ddos-panel/data
mkdir -p /opt/ddos-panel/public
mkdir -p /etc/nginx/sites-dynamic
mkdir -p /etc/nginx/conf.d

# Copy application files
cp engine.php /opt/ddos-panel/
cp cf-sync-ban.php /opt/ddos-panel/
cp public/index.php /opt/ddos-panel/public/
cp scripts/f2b-nginx-block.sh /usr/local/bin/f2b-nginx-block.sh
chmod +x /usr/local/bin/f2b-nginx-block.sh

# 4. Configure Sudoers for www-data
echo "[*] Configuring sudo privileges for www-data..."
cat << 'EOF' > /etc/sudoers.d/nginx-panel
www-data ALL=(ALL) NOPASSWD: /usr/sbin/nginx, /usr/bin/systemctl reload nginx, /usr/bin/systemctl restart nginx, /usr/bin/systemctl is-active nginx, /usr/bin/systemctl restart fail2ban, /usr/bin/systemctl is-active fail2ban, /usr/bin/fail2ban-client, /usr/sbin/ufw, /usr/sbin/nft
EOF
chmod 0440 /etc/sudoers.d/nginx-panel

# 5. Setup Fail2ban Action & Configuration
echo "[*] Setting up Fail2ban action and jails..."
cat << 'EOF' > /etc/fail2ban/action.d/nginx-block.conf
[Definition]
actionstart = touch /etc/nginx/conf.d/fail2ban-denylist.conf
actionstop = 
actioncheck = 
actionban = /usr/local/bin/f2b-nginx-block.sh ban '<ip>'
actionunban = /usr/local/bin/f2b-nginx-block.sh unban '<ip>'
EOF

touch /etc/nginx/conf.d/fail2ban-denylist.conf
cp conf/anti-ddos-limits.conf /etc/nginx/conf.d/anti-ddos-limits.conf
cp conf/jail.local /etc/fail2ban/jail.local

# 6. Setup Nginx VirtualHosts
echo "[*] Setting up Nginx panel vhost..."
sed -i "s/php8.3-fpm/php${PHP_VER}-fpm/g" conf/nginx-panel.conf
cp conf/nginx-panel.conf /etc/nginx/sites-available/ddos-panel.conf
ln -sf /etc/nginx/sites-available/ddos-panel.conf /etc/nginx/sites-enabled/ddos-panel.conf

# Include dynamic sites in nginx.conf if not present
if ! grep -Fq "include /etc/nginx/sites-dynamic/*;" /etc/nginx/nginx.conf; then
    sed -i '/include \/etc\/nginx\/sites-enabled\/\*;/a \    include /etc/nginx/sites-dynamic/*;' /etc/nginx/nginx.conf
fi

# 7. Initialize Database and Set Permissions
echo "[*] Initializing SQLite database and setting file permissions..."
php -r 'require_once "/opt/ddos-panel/engine.php"; PanelEngine::init();'
chown -R www-data:www-data /opt/ddos-panel
chmod -R 775 /opt/ddos-panel/data
chmod 664 /opt/ddos-panel/data/panel.db 2>/dev/null || true

# 8. Restart & Enable Services
echo "[*] Restarting services..."
nginx -t
systemctl restart php${PHP_VER}-fpm
systemctl restart nginx
systemctl restart fail2ban
systemctl enable nginx fail2ban php${PHP_VER}-fpm

echo "======================================================================"
echo " [SUCCESS] Anti-DDoS & Cloudflare Panel Installed Successfully!"
echo " Access your panel at: http://YOUR_SERVER_IP:8080"
echo " Default Username: admin"
echo " Default Password: admin123"
echo " (Please change the default password immediately after login)"
echo "======================================================================"
