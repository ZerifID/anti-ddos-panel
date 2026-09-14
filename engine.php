<?php
class CloudflareAPI {
    private static function request($method, $endpoint, $apiKey, $apiEmail, $data = null) {
        $ch = curl_init("https://api.cloudflare.com/client/v4" . $endpoint);
        $headers = [
            "X-Auth-Key: {$apiKey}",
            "X-Auth-Email: {$apiEmail}",
            "Content-Type: application/json"
        ];
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        if ($data !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $json = json_decode($response, true);
        return [
            'code' => $httpCode,
            'success' => ($httpCode >= 200 && $httpCode < 300 && ($json['success'] ?? false)),
            'data' => $json['result'] ?? null,
            'errors' => $json['errors'] ?? []
        ];
    }

    public static function getZones($apiKey, $apiEmail) {
        $res = self::request('GET', '/zones?status=active&per_page=50', $apiKey, $apiEmail);
        return $res['success'] ? $res['data'] : [];
    }

    public static function getZoneDetails($zoneId, $apiKey, $apiEmail) {
        $res = self::request('GET', "/zones/{$zoneId}", $apiKey, $apiEmail);
        return $res['success'] ? $res['data'] : null;
    }

    public static function purgeCache($zoneId, $apiKey, $apiEmail) {
        return self::request('POST', "/zones/{$zoneId}/purge_cache", $apiKey, $apiEmail, ['purge_everything' => true]);
    }

    public static function getIpAccessRules($zoneId, $apiKey, $apiEmail) {
        $res = self::request('GET', "/zones/{$zoneId}/firewall/access_rules/rules?per_page=100", $apiKey, $apiEmail);
        return $res['success'] ? $res['data'] : [];
    }

    public static function addIpAccessRule($zoneId, $apiKey, $apiEmail, $ip, $mode = 'block', $notes = 'Banned by Anti-DDoS Panel') {
        $payload = [
            'mode' => $mode,
            'configuration' => [
                'target' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ip6' : 'ip',
                'value' => $ip
            ],
            'notes' => $notes
        ];
        return self::request('POST', "/zones/{$zoneId}/firewall/access_rules/rules", $apiKey, $apiEmail, $payload);
    }

    public static function deleteIpAccessRule($zoneId, $apiKey, $apiEmail, $ruleId) {
        return self::request('DELETE', "/zones/{$zoneId}/firewall/access_rules/rules/{$ruleId}", $apiKey, $apiEmail);
    }

    public static function ensureOtpIdp($accountId, $apiKey, $apiEmail) {
        $res = self::request('GET', "/accounts/{$accountId}/access/identity_providers", $apiKey, $apiEmail);
        if ($res['success'] && is_array($res['data'])) {
            foreach ($res['data'] as $idp) {
                if (($idp['type'] ?? '') === 'onetimepin') {
                    return $idp['id'];
                }
            }
        }
        $createRes = self::request('POST', "/accounts/{$accountId}/access/identity_providers", $apiKey, $apiEmail, [
            'type' => 'onetimepin',
            'name' => 'One-Time PIN',
            'config' => new stdClass()
        ]);
        if ($createRes['success'] && isset($createRes['data']['id'])) {
            return $createRes['data']['id'];
        }
        return null;
    }

    public static function getAccessApps($accountId, $apiKey, $apiEmail) {
        $res = self::request('GET', "/accounts/{$accountId}/access/apps", $apiKey, $apiEmail);
        return $res['success'] ? $res['data'] : [];
    }

    public static function createAccessApp($accountId, $apiKey, $apiEmail, $name, $domain, $emails = [], $allowedIdps = []) {
        $payload = [
            'name' => $name,
            'domain' => $domain,
            'type' => 'self_hosted',
            'session_duration' => '24h',
            'auto_redirect_to_identity' => true
        ];
        if (!empty($allowedIdps)) {
            $payload['allowed_idps'] = $allowedIdps;
        }
        $appRes = self::request('POST', "/accounts/{$accountId}/access/apps", $apiKey, $apiEmail, $payload);
        if (!$appRes['success'] || !isset($appRes['data']['id'])) {
            return $appRes;
        }
        $appId = $appRes['data']['id'];
        $includeRules = [];
        foreach ($emails as $email) {
            $email = trim($email);
            if (empty($email)) continue;
            if (strpos($email, '@') === false && strpos($email, '.') !== false) {
                $includeRules[] = ['email_domain' => ['domain' => $email]];
            } else {
                $includeRules[] = ['email' => ['email' => $email]];
            }
        }
        if (empty($includeRules)) {
            $includeRules[] = ['everyone' => new stdClass()];
        }
        $policyPayload = [
            'name' => 'Allow Authorized Users',
            'decision' => 'allow',
            'include' => $includeRules
        ];
        self::request('POST', "/accounts/{$accountId}/access/apps/{$appId}/policies", $apiKey, $apiEmail, $policyPayload);
        return $appRes;
    }

    public static function deleteAccessApp($accountId, $apiKey, $apiEmail, $appId) {
        return self::request('DELETE', "/accounts/{$accountId}/access/apps/{$appId}", $apiKey, $apiEmail);
    }
}

class PanelEngine {
    private static $dbPath = '/opt/ddos-panel/data/panel.db';

    public static function getDB() {
        $db = new SQLite3(self::$dbPath);
        $db->busyTimeout(5000);
        return $db;
    }

    public static function init() {
        $db = self::getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS vhosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            target_ip TEXT,
            target_port INTEGER,
            rate_limit INTEGER DEFAULT 30,
            rate_burst INTEGER DEFAULT 20,
            enable_waf INTEGER DEFAULT 1,
            enable_challenge INTEGER DEFAULT 0,
            custom_error INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )");

        $defaults = [
            'admin_password' => password_hash('admin123', PASSWORD_BCRYPT),
            'cf_api_key' => '',
            'cf_api_email' => '',
            'cf_account_id' => '',
            'cf_default_zone_id' => '',
            'cf_auto_sync_ban' => '1',
            'cf_auto_ban_mode' => 'block',
            'global_rate_limit' => '30',
            'global_burst' => '50',
            'ban_time' => '3600',
            'find_time' => '600',
            'max_retry' => '5'
        ];

        foreach ($defaults as $k => $v) {
            $stmt = $db->prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (:key, :val)");
            $stmt->bindValue(':key', $k, SQLITE3_TEXT);
            $stmt->bindValue(':val', $v, SQLITE3_TEXT);
            $stmt->execute();
        }
    }

    public static function getSettings() {
        $db = self::getDB();
        $res = $db->query("SELECT * FROM settings");
        $settings = [];
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $settings[$row['key']] = $row['value'];
        }
        return $settings;
    }

    public static function generateNginxConfig($vhost) {
        $domain = $vhost['domain'];
        $targetIp = $vhost['target_ip'];
        $targetPort = $vhost['target_port'];
        $rateLimit = $vhost['rate_limit'] ?: 30;
        $rateBurst = $vhost['rate_burst'] ?: 20;
        $enableWaf = $vhost['enable_waf'] ? 'on' : 'off';

        $conf = <<<EOC
# Dynamic VirtualHost for {$domain}
# Managed by Anti-DDoS Control Panel

server {
    listen 80;
    listen [::]:80;
    server_name {$domain};

    # Real IP Resolution from Cloudflare Proxy & Localhost
    set_real_ip_from 127.0.0.1;
    set_real_ip_from 100.64.0.0/10;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    real_ip_header CF-Connecting-IP;

    limit_req zone=ddos_limit burst={$rateBurst} nodelay;
    limit_conn ddos_conn 50;

    access_log /var/log/nginx/{$domain}_access.log combined;
    error_log /var/log/nginx/{$domain}_error.log warn;

    location / {
        include /etc/nginx/conf.d/fail2ban-denylist.conf;

        proxy_pass http://{$targetIp}:{$targetPort};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOC;
        return $conf;
    }

    public static function syncFail2banConfig() {
        $settings = self::getSettings();
        $banTime = $settings['ban_time'] ?? 3600;
        $findTime = $settings['find_time'] ?? 600;
        $maxRetry = $settings['max_retry'] ?? 5;

        $jailLocal = <<<EOC
[DEFAULT]
bantime  = {$banTime}
findtime  = {$findTime}
maxretry = {$maxRetry}
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 192.168.1.0/24 100.64.0.0/10
backend = auto
usedns = warn
logencoding = utf-8
enabled = false
banaction = nftables-multiport
banaction_allports = nftables-allports

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[nginx-limit-req]
enabled = true
port    = http,https
logpath = /var/log/nginx/*error.log
action  = %(default/action)s[name=nginx-limit-req]
          nginx-block[name=nginx-limit-req]

[nginx-botsearch]
enabled = true
port     = http,https
logpath  = /var/log/nginx/*access.log
maxretry = 2
action   = %(default/action)s[name=nginx-botsearch]
           nginx-block[name=nginx-botsearch]

[nginx-http-auth]
enabled = true
port    = http,https
logpath = /var/log/nginx/*error.log
action  = %(default/action)s[name=nginx-http-auth]
          nginx-block[name=nginx-block]
EOC;

        file_put_contents('/etc/fail2ban/jail.local', $jailLocal);
        shell_exec('sudo systemctl restart fail2ban 2>&1');
    }
}
