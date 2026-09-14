<?php
// /opt/ddos-panel/engine.php

class CloudflareAPI {
    public static function request($endpoint, $method = 'GET', $data = [], $apiKey = '', $apiEmail = '') {
        $ch = curl_init('https://api.cloudflare.com/client/v4' . $endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_TIMEOUT, 12);
        
        $headers = ['Content-Type: application/json'];
        if (!empty($apiEmail) && !empty($apiKey)) {
            $headers[] = 'X-Auth-Key: ' . trim($apiKey);
            $headers[] = 'X-Auth-Email: ' . trim($apiEmail);
        } elseif (!empty($apiKey)) {
            $headers[] = 'Authorization: Bearer ' . trim($apiKey);
        } else {
            return ['success' => false, 'errors' => [['message' => 'Cloudflare API Key belum dikonfigurasi']]];
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        if (!empty($data) && ($method === 'POST' || $method === 'PUT' || $method === 'PATCH')) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }

        $response = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);

        if ($err) {
            return ['success' => false, 'errors' => [['message' => 'cURL error: ' . $err]]];
        }

        $json = json_decode($response, true);
        return $json ? $json : ['success' => false, 'errors' => [['message' => 'Invalid JSON response from Cloudflare']]];
    }

    public static function getZones($apiKey, $apiEmail = '') {
        return self::request('/zones?per_page=50', 'GET', [], $apiKey, $apiEmail);
    }

    public static function getSecurityLevel($zoneId, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/settings/security_level", 'GET', [], $apiKey, $apiEmail);
    }

    public static function setSecurityLevel($zoneId, $level, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/settings/security_level", 'PATCH', ['value' => $level], $apiKey, $apiEmail);
    }

    public static function getIpAccessRules($zoneId, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/firewall/access_rules/rules?per_page=50", 'GET', [], $apiKey, $apiEmail);
    }

    public static function blockIpOnCloudflare($zoneId, $ip, $mode = 'block', $notes = 'Blocked via Anti-DDoS Panel', $apiKey = '', $apiEmail = '') {
        $payload = [
            'mode' => $mode,
            'configuration' => [
                'target' => 'ip',
                'value' => $ip
            ],
            'notes' => $notes
        ];
        return self::request("/zones/{$zoneId}/firewall/access_rules/rules", 'POST', $payload, $apiKey, $apiEmail);
    }

    public static function deleteIpAccessRule($zoneId, $ruleId, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/firewall/access_rules/rules/{$ruleId}", 'DELETE', [], $apiKey, $apiEmail);
    }

    public static function deleteIpAccessRuleByIp($zoneId, $ip, $apiKey, $apiEmail = '') {
        $rules = self::getIpAccessRules($zoneId, $apiKey, $apiEmail);
        if (!empty($rules['result'])) {
            foreach ($rules['result'] as $r) {
                if (isset($r['configuration']['value']) && $r['configuration']['value'] === $ip) {
                    self::deleteIpAccessRule($zoneId, $r['id'], $apiKey, $apiEmail);
                }
            }
        }
        return true;
    }

    public static function deleteAllIpAccessRules($zoneId, $apiKey, $apiEmail = '') {
        $totalDeleted = 0;
        $maxLoops = 20; // safety limit to prevent infinite loops
        $loop = 0;

        while ($loop < $maxLoops) {
            $loop++;
            $rules = self::getIpAccessRules($zoneId, $apiKey, $apiEmail);
            $items = $rules['result'] ?? [];
            if (empty($items)) {
                break;
            }

            foreach ($items as $r) {
                if (isset($r['id'])) {
                    $delRes = self::deleteIpAccessRule($zoneId, $r['id'], $apiKey, $apiEmail);
                    if (!empty($delRes['success'])) {
                        $totalDeleted++;
                    }
                    usleep(50000); // 50ms pause to avoid Cloudflare rate limits (code 971)
                }
            }
        }

        // Also ensure Custom WAF ruleset is empty
        try {
            self::request("/zones/{$zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint", 'PUT', ['rules' => []], $apiKey, $apiEmail);
        } catch (Exception $e) {}

        return ['status' => true, 'deleted_count' => $totalDeleted];
    }

    public static function purgeCache($zoneId, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/purge_cache", 'POST', ['purge_everything' => true], $apiKey, $apiEmail);
    }

    // CLOUDFLARE ZERO TRUST ACCESS APIS
    public static function getAccessApps($zoneId, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/access/apps?per_page=50", 'GET', [], $apiKey, $apiEmail);
    }

    public static function ensureOtpIdp($zoneId, $apiKey, $apiEmail = '') {
        $zRes = self::request("/zones/{$zoneId}", 'GET', [], $apiKey, $apiEmail);
        $accountId = $zRes['result']['account']['id'] ?? '';
        if (empty($accountId)) return null;

        $idps = self::request("/accounts/{$accountId}/access/identity_providers", 'GET', [], $apiKey, $apiEmail);
        if (!empty($idps['result'])) {
            foreach ($idps['result'] as $idp) {
                if ($idp['type'] === 'onetimepin') {
                    return $idp['id'];
                }
            }
        }

        $otpRes = self::request("/accounts/{$accountId}/access/identity_providers", 'POST', [
            'name' => 'One-time PIN',
            'type' => 'onetimepin',
            'config' => new stdClass()
        ], $apiKey, $apiEmail);

        return $otpRes['result']['id'] ?? null;
    }

    public static function createAccessApp($zoneId, $name, $domain, $sessionDuration = '24h', $apiKey = '', $apiEmail = '') {
        $otpId = self::ensureOtpIdp($zoneId, $apiKey, $apiEmail);
        $payload = [
            'name' => $name,
            'domain' => $domain,
            'type' => 'self_hosted',
            'session_duration' => $sessionDuration,
            'auto_redirect_to_identity' => false
        ];

        if (!empty($otpId)) {
            $payload['allowed_idps'] = [$otpId];
        }

        return self::request("/zones/{$zoneId}/access/apps", 'POST', $payload, $apiKey, $apiEmail);
    }

    public static function getAccessPolicies($zoneId, $appId, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/access/apps/{$appId}/policies", 'GET', [], $apiKey, $apiEmail);
    }

    public static function createAccessPolicy($zoneId, $appId, $name, $decision, $includeEmails = [], $apiKey = '', $apiEmail = '') {
        $includeList = [];
        foreach ($includeEmails as $em) {
            $em = trim($em);
            if (!empty($em)) {
                if ($em === '*' || strtolower($em) === 'everyone') {
                    $includeList[] = ['everyone' => new stdClass()];
                } elseif (strpos($em, '@') !== false && !str_starts_with($em, '@')) {
                    $includeList[] = ['email' => ['email' => $em]];
                } else {
                    $domainPart = ltrim($em, '@');
                    $includeList[] = ['email_domain' => ['domain' => $domainPart]];
                }
            }
        }

        if (empty($includeList)) {
            $includeList[] = ['everyone' => new stdClass()];
        }

        $payload = [
            'name' => $name,
            'decision' => $decision,
            'include' => $includeList
        ];
        return self::request("/zones/{$zoneId}/access/apps/{$appId}/policies", 'POST', $payload, $apiKey, $apiEmail);
    }

    public static function deleteAccessApp($zoneId, $appId, $apiKey, $apiEmail = '') {
        return self::request("/zones/{$zoneId}/access/apps/{$appId}", 'DELETE', [], $apiKey, $apiEmail);
    }
}

class PanelEngine {
    private static $dbPath = '/opt/ddos-panel/data/panel.db';
    private static $confDir = '/etc/nginx/sites-dynamic';

    public static function getDB() {
        $db = new PDO('sqlite:' . self::$dbPath);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $db;
    }

    public static function initDB() {
        $db = self::getDB();
        $db->exec("
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                target_type TEXT NOT NULL, -- 'local_php' or 'proxy'
                target_value TEXT NOT NULL, -- path or http://ip:port
                custom_rate_limit INTEGER DEFAULT 0, -- 0 means follow global
                custom_rate_burst INTEGER DEFAULT 0,
                custom_conn_limit INTEGER DEFAULT 0,
                is_wildcard INTEGER DEFAULT 0,
                cf_zone_id TEXT DEFAULT '',
                require_zt_access INTEGER DEFAULT 0,
                status INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ");

        try {
            $db->exec("ALTER TABLE domains ADD COLUMN cf_zone_id TEXT DEFAULT ''");
        } catch (Exception $e) {}

        try {
            $db->exec("ALTER TABLE domains ADD COLUMN require_zt_access INTEGER DEFAULT 0");
        } catch (Exception $e) {}

        try {
            $db->exec("ALTER TABLE domains ADD COLUMN geoip_mode TEXT DEFAULT 'off'");
        } catch (Exception $e) {}

        try {
            $db->exec("ALTER TABLE domains ADD COLUMN geoip_countries TEXT DEFAULT ''");
        } catch (Exception $e) {}

        // Default Settings
        $defaults = [
            'admin_password' => password_hash('admin123', PASSWORD_BCRYPT),
            'global_server_rate' => '100r/s',
            'global_server_burst' => '150',
            'global_client_rate' => '10r/s',
            'global_client_burst' => '20',
            'global_conn_limit' => '25',
            'fail2ban_bantime' => '10m',
            'fail2ban_findtime' => '1m',
            'fail2ban_maxretry' => '5',
            'block_bad_bots' => '1',
            'block_hidden_files' => '1',
            'cf_api_key' => '',
            'cf_api_email' => '',
            'cf_default_zone_id' => '',
            'cf_auto_sync_ban' => '1',
            'cf_auto_ban_mode' => 'block' // 'block' or 'challenge'
        ];

        foreach ($defaults as $k => $v) {
            $stmt = $db->prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)");
            $stmt->execute([$k, $v]);
        }
    }

    public static function getSettings() {
        $db = self::getDB();
        $stmt = $db->query("SELECT * FROM settings");
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $settings = [];
        foreach ($results as $row) {
            $settings[$row['key']] = $row['value'];
        }
        return $settings;
    }

    public static function syncFail2ban() {
        $settings = self::getSettings();
        $bantime = !empty($settings['fail2ban_bantime']) ? $settings['fail2ban_bantime'] : '10m';
        $findtime = !empty($settings['fail2ban_findtime']) ? $settings['fail2ban_findtime'] : '1m';
        $maxretry = !empty($settings['fail2ban_maxretry']) ? intval($settings['fail2ban_maxretry']) : 5;

        $jailConfig = "[DEFAULT]
# Whitelist local, internal, and tailscale IP ranges
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10

# Ban duration & detection window
bantime = {$bantime}
findtime = {$findtime}
maxretry = {$maxretry}
banaction = nginx-block

[sshd]
enabled = true
port = ssh
maxretry = 3
findtime = 10m
bantime = 24h

[nginx-http-auth]
enabled = true
port = http,https
logpath = %(nginx_error_log)s

[nginx-botsearch]
enabled = true
port = http,https
logpath = %(nginx_error_log)s
maxretry = 2
bantime = {$bantime}

[nginx-limit-req]
enabled = true
port = http,https
logpath = %(nginx_error_log)s
findtime = {$findtime}
bantime = {$bantime}
maxretry = {$maxretry}
";

        file_put_contents('/etc/fail2ban/jail.local', $jailConfig);
        exec('sudo /usr/bin/fail2ban-client reload 2>&1');
        return true;
    }

    public static function syncNginx() {
        if (!is_dir(self::$confDir)) {
            mkdir(self::$confDir, 0755, true);
        }

        $db = self::getDB();
        $settings = self::getSettings();
        $domains = $db->query("SELECT * FROM domains WHERE status = 1")->fetchAll(PDO::FETCH_ASSOC);

        // 1. Generate Global Zones config (/etc/nginx/conf.d/dynamic-zones.conf)
        $clientRate = !empty($settings['global_client_rate']) ? $settings['global_client_rate'] : '10r/s';
        $globalZoneConf = "# Generated by Anti-DDoS Panel\n";
        $globalZoneConf .= "limit_req_zone \$binary_remote_addr zone=panel_client_global:20m rate={$clientRate};\n";
        $globalZoneConf .= "limit_conn_zone \$binary_remote_addr zone=panel_conn_global:20m;\n";

        // Domain specific zones if any custom limits
        foreach ($domains as $d) {
            if ($d['custom_rate_limit'] > 0) {
                $zoneName = 'zone_domain_' . $d['id'];
                $rate = $d['custom_rate_limit'] . 'r/s';
                $globalZoneConf .= "limit_req_zone \$binary_remote_addr zone={$zoneName}:10m rate={$rate};\n";
            }
        }

        file_put_contents('/etc/nginx/conf.d/dynamic-zones.conf', $globalZoneConf);

        // 2. Clean old dynamic site configs
        $oldFiles = glob(self::$confDir . '/*.conf');
        foreach ($oldFiles as $f) {
            unlink($f);
        }

        // 3. Generate each domain config
        $globalClientBurst = !empty($settings['global_client_burst']) ? $settings['global_client_burst'] : '20';
        $globalConnLimit = !empty($settings['global_conn_limit']) ? $settings['global_conn_limit'] : '25';
        $blockBots = ($settings['block_bad_bots'] ?? '1') === '1';
        $blockHidden = ($settings['block_hidden_files'] ?? '1') === '1';

        foreach ($domains as $d) {
            $serverNames = $d['domain'];
            if (!empty($d['is_wildcard'])) {
                $serverNames = "{$d['domain']} *.{$d['domain']}";
            }

            $reqLimitDirectives = "";
            $connLimitDirectives = "";

            if ($d['custom_rate_limit'] > 0) {
                $zoneName = 'zone_domain_' . $d['id'];
                $burst = $d['custom_rate_burst'] > 0 ? $d['custom_rate_burst'] : ($d['custom_rate_limit'] * 2);
                $reqLimitDirectives = "limit_req zone={$zoneName} burst={$burst} nodelay;";
            } else {
                $reqLimitDirectives = "limit_req zone=panel_client_global burst={$globalClientBurst} nodelay;";
            }

            if ($d['custom_conn_limit'] > 0) {
                $connLimitDirectives = "limit_conn panel_conn_global {$d['custom_conn_limit']};";
            } else {
                $connLimitDirectives = "limit_conn panel_conn_global {$globalConnLimit};";
            }

            $securityBlocks = "";
            if ($blockBots) {
                $securityBlocks .= "
    if (\$http_user_agent ~* (nikto|sqlmap|nmap|w3af|acunetix|nessus|dirbuster|gobuster|masscan|zgrab)) {
        return 403;
    }
";
            }

            if ($blockHidden) {
                $securityBlocks .= "
    location ~ /\\.(?!well-known).* {
        deny all;
        access_log off;
        log_not_found off;
    }
    location ~* \\.(env|git|htaccess|sql|bak|config|json|yml|yaml|ini|log|sh)$ {
        deny all;
        access_log off;
        log_not_found off;
    }
";
            }

            // Zero Trust Strict Enforcer
            $ztAccessBlock = "";
            if (!empty($d['require_zt_access'])) {
                $ztAccessBlock = "
    # Cloudflare Zero Trust Enforcement (Drop request jika tidak melewati Cloudflare Access OTP)
    if (\$http_cf_access_jwt_assertion = \"\") {
        return 403 \"403 Forbidden: Cloudflare Zero Trust Authentication Required\";
    }
";
            }

            $siteConf = "# Domain: {$d['domain']}\n";
            $siteConf .= "server {\n";
            $siteConf .= "    listen 80;\n";
            $siteConf .= "    server_name {$serverNames};\n\n";
            $siteConf .= "    {$reqLimitDirectives}\n";
            $siteConf .= "    {$connLimitDirectives}\n";
            $siteConf .= "    {$securityBlocks}\n";
            $siteConf .= "    {$ztAccessBlock}\n";

            if ($d['target_type'] === 'proxy') {
                $proxyUrl = $d['target_value'];
                $siteConf .= "    location / {\n";
                $siteConf .= "        proxy_pass {$proxyUrl};\n";
                $siteConf .= "        proxy_set_header Host \$host;\n";
                $siteConf .= "        proxy_set_header X-Real-IP \$remote_addr;\n";
                $siteConf .= "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n";
                $siteConf .= "        proxy_set_header X-Forwarded-Proto \$scheme;\n";
                $siteConf .= "        proxy_http_version 1.1;\n";
                $siteConf .= "        proxy_set_header Upgrade \$http_upgrade;\n";
                $siteConf .= "        proxy_set_header Connection \"upgrade\";\n";
                $siteConf .= "        proxy_connect_timeout 60s;\n";
                $siteConf .= "        proxy_read_timeout 60s;\n";
                $siteConf .= "        proxy_send_timeout 60s;\n";
                $siteConf .= "    }\n";
            } else {
                $docRoot = !empty($d['target_value']) ? $d['target_value'] : '/var/www/html';
                $siteConf .= "    root {$docRoot};\n";
                $siteConf .= "    index index.php index.html index.htm;\n\n";
                $siteConf .= "    location / {\n";
                $siteConf .= "        try_files \$uri \$uri/ /index.php?\$query_string;\n";
                $siteConf .= "    }\n\n";
                $siteConf .= "    location ~ \\.php$ {\n";
                $siteConf .= "        include snippets/fastcgi-php.conf;\n";
                $siteConf .= "        fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n";
                $siteConf .= "        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;\n";
                $siteConf .= "        include fastcgi_params;\n";
                $siteConf .= "    }\n";
            }

            $siteConf .= "}\n";

            $cleanFileName = preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $d['domain']);
            file_put_contents(self::$confDir . "/domain_{$cleanFileName}.conf", $siteConf);
        }

        // Test Nginx Config
        $testOut = shell_exec('sudo /usr/sbin/nginx -t 2>&1');
        if (strpos($testOut, 'syntax is ok') !== false && strpos($testOut, 'test is successful') !== false) {
            shell_exec('sudo /usr/sbin/nginx -s reload');
            self::syncFail2ban();
            return ['status' => true, 'message' => 'Nginx & Fail2ban berhasil disinkronkan dan direload!'];
        } else {
            return ['status' => false, 'message' => 'Nginx Test Gagal: ' . $testOut];
        }
    }
}
