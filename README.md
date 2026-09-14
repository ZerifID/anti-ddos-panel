# 🛡️ Anti-DDoS & Cloudflare Zero Trust Management Panel

A high-performance, lightweight **Nginx Reverse Proxy Management Panel** featuring automated multi-layer Anti-DDoS mitigation, dynamic rate-limiting, Fail2ban integration, and bidirectional synchronization with **Cloudflare Edge WAF & Zero Trust Access OTP**.

---

## ✨ Features

- 🚀 **Dynamic Reverse Proxy Manager:** Create and manage Nginx reverse proxy vhosts on the fly with per-domain rate-limits, burst controls, and SSL support.
- 🛡️ **Multi-Layer Anti-DDoS:**
  - **Nginx Leaky-Bucket Rate Limiting:** Granular connection and request limits with `limit_req` and `limit_conn`.
  - **Fail2ban Integration:** Automatic jail monitoring for `nginx-limit-req`, `nginx-botsearch`, `nginx-http-auth`, and `sshd`.
  - **Native nftables/iptables:** Kernel-level packet filtering for direct traffic.
- ⚡ **Auto-Deploy to Cloudflare Edge WAF:**
  - Real-time synchronization: Whenever an IP is banned locally by Fail2ban, it is immediately pushed to **Cloudflare IP Access Rules** (`Block`, `Managed Challenge`, or `JS Challenge`).
  - Dual-Layer Auto-Unban: When an IP is unbanned (or expires), the rule is automatically purged from both local Nginx denylists and Cloudflare Edge WAF.
- 🔐 **Cloudflare Zero Trust Access OTP Generator:**
  - One-click deployment of Cloudflare Access applications for your domains/subdomains.
  - Dedicated email OTP (`onetimepin`) authentication flow for secure access control.
- 📊 **Real-time Live Monitoring:**
  - Live CPU, RAM, Disk, and Network traffic usage.
  - Active connections count and request metrics.
  - Interactive Ban Monitor with instant manual ban/unban and direct Cloudflare WAF push.
- 🎨 **Modern Responsive UI:** Built with Tailwind CSS, Alpine.js, Lucide Icons, and dark theme support.

---

## 📋 System Requirements

- **Operating System:** Ubuntu 20.04 / 22.04 / 24.04 LTS or Debian 11 / 12
- **Web Server:** Nginx
- **PHP:** PHP 8.1+ (with `php-fpm`, `php-sqlite3`, `php-curl`)
- **Security:** Fail2ban, nftables / iptables
- **Cloudflare Account:** Global API Key or API Token (with Zone/Access edit permissions)

---

## 🚀 Quick Installation

Run the automated installation script as `root`:

```bash
# Clone the repository
git clone https://github.com/ZerifID/anti-ddos-panel.git
cd anti-ddos-panel

# Run installer
sudo bash install.sh
```

Once installation finishes, open your browser and navigate to:
```text
http://YOUR_SERVER_IP:8080
```

- **Default Username:** `admin`
- **Default Password:** `admin123`

*(⚠️ Make sure to change your password immediately after your first login via the Settings tab!)*

---

## 📁 Repository Structure

```text
anti-ddos-panel/
├── install.sh                  # One-click auto-installer script
├── engine.php                  # Core backend engine (Cloudflare API & Nginx generator)
├── cf-sync-ban.php             # Background event hook for Cloudflare WAF auto-sync
├── scripts/
│   └── f2b-nginx-block.sh      # Fail2ban action script for Nginx & Cloudflare
├── conf/
│   ├── jail.local              # Fail2ban multi-jail configuration
│   ├── nginx-panel.conf        # Nginx virtual host for the dashboard panel
│   └── anti-ddos-limits.conf   # Global Nginx rate limiting zones
├── public/
│   └── index.php               # Single-page Web UI Dashboard (Tailwind + Alpine.js)
├── .gitignore                  # Git ignore rules for database and cache files
└── README.md                   # Project documentation
```

---

## ⚙️ Configuration & Cloudflare Setup

1. Log in to the panel and navigate to the **Cloudflare Shield & Zero Trust** tab.
2. Enter your:
   - **Cloudflare API Email**
   - **Cloudflare API Key / Token**
   - **Cloudflare Account ID**
3. Select your active Cloudflare Zone.
4. Under **Local Limits & Ban Settings**, toggle `Auto-Deploy Banned IP ke Cloudflare Edge WAF` to enable automatic edge-level blocking.

---

## 🔒 Security Best Practices

1. **Protect Panel Port (`8080`):** Use a firewall (UFW/nftables), VPN (such as Tailscale/WireGuard), or a Cloudflare Zero Trust Tunnel to restrict access to port 8080.
2. **Tunnel Ingress:** If routing through Cloudflare Tunnel, ensure your ingress rule forwards to `http://127.0.0.1:80` with `httpHostHeader` enabled.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
