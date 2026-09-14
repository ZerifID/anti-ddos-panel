<?php
// /opt/ddos-panel/public/index.php
session_start();
require_once __DIR__ . '/../engine.php';

PanelEngine::initDB();

// Simple Auth Check
$isLoggedIn = !empty($_SESSION['logged_in']);
$db = PanelEngine::getDB();
$settings = PanelEngine::getSettings();

// Handle AJAX API requests
if (isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    if ($_GET['api'] === 'login') {
        $data = json_decode(file_get_contents('php://input'), true);
        $pass = $data['password'] ?? '';
        if (password_verify($pass, $settings['admin_password'])) {
            $_SESSION['logged_in'] = true;
            echo json_encode(['status' => true]);
        } else {
            echo json_encode(['status' => false, 'message' => 'Password salah!']);
        }
        exit;
    }

    if (!$isLoggedIn) {
        http_response_code(401);
        echo json_encode(['status' => false, 'message' => 'Unauthorized']);
        exit;
    }

    if ($_GET['api'] === 'logout') {
        $_SESSION['logged_in'] = false;
        session_destroy();
        echo json_encode(['status' => true]);
        exit;
    }

    if ($_GET['api'] === 'get_data') {
        $domains = $db->query("SELECT * FROM domains ORDER BY id DESC")->fetchAll(PDO::FETCH_ASSOC);
        
        // System status
        $nginxStatus = shell_exec('sudo systemctl is-active nginx 2>/dev/null') ? trim(shell_exec('sudo systemctl is-active nginx 2>/dev/null')) : 'unknown';
        $phpStatus = shell_exec('sudo systemctl is-active php8.3-fpm 2>/dev/null') ? trim(shell_exec('sudo systemctl is-active php8.3-fpm 2>/dev/null')) : 'unknown';
        $fail2banStatus = shell_exec('sudo systemctl is-active fail2ban 2>/dev/null') ? trim(shell_exec('sudo systemctl is-active fail2ban 2>/dev/null')) : 'unknown';
        $ufwStatus = shell_exec('sudo ufw status 2>/dev/null | head -n 1');

        // Banned IPs
        $bannedIps = [];
        $fail2banOut = shell_exec('sudo fail2ban-client status 2>/dev/null');
        if (preg_match('/Jail list:\s+(.*)/', $fail2banOut ?? '', $matches)) {
            $jails = explode(',', $matches[1]);
            foreach ($jails as $jail) {
                $jail = trim($jail);
                $jStatus = shell_exec("sudo fail2ban-client status {$jail} 2>/dev/null");
                if (preg_match('/Banned IP list:\s+(.*)/', $jStatus ?? '', $mIp)) {
                    $ips = array_filter(explode(' ', trim($mIp[1])));
                    foreach ($ips as $ip) {
                        $bannedIps[] = ['ip' => $ip, 'jail' => $jail];
                    }
                }
            }
        }

        echo json_encode([
            'status' => true,
            'settings' => $settings,
            'domains' => $domains,
            'banned_ips' => $bannedIps,
            'system' => [
                'nginx' => $nginxStatus,
                'php' => $phpStatus,
                'fail2ban' => $fail2banStatus,
                'ufw' => trim($ufwStatus ?? '')
            ]
        ]);
        exit;
    }

    if ($_GET['api'] === 'get_logs') {
        $type = $_GET['type'] ?? 'access';
        $filter = trim($_GET['filter'] ?? '');
        $lines = min(max(intval($_GET['lines'] ?? 50), 10), 300);

        $logFile = ($type === 'error') ? '/var/log/nginx/error.log' : '/var/log/nginx/access.log';
        if ($type === 'ddos') {
            $cmd = "grep -i 'limiting requests' /var/log/nginx/error.log | tail -n {$lines}";
        } else {
            $cmd = "tail -n {$lines} {$logFile}";
        }

        $rawLogs = shell_exec($cmd) ?? '';
        $logLines = array_filter(explode("\n", trim($rawLogs)));

        if (!empty($filter)) {
            $logLines = array_filter($logLines, function($line) use ($filter) {
                return stripos($line, $filter) !== false;
            });
        }

        echo json_encode([
            'status' => true,
            'type' => $type,
            'total' => count($logLines),
            'logs' => array_values(array_reverse($logLines))
        ]);
        exit;
    }

    if ($_GET['api'] === 'clear_logs') {
        $type = $_GET['type'] ?? 'all';
        if ($type === 'access' || $type === 'all') {
            file_put_contents('/var/log/nginx/access.log', '');
        }
        if ($type === 'error' || $type === 'all') {
            file_put_contents('/var/log/nginx/error.log', '');
        }
        echo json_encode(['status' => true, 'message' => 'Log berhasil dibersihkan']);
        exit;
    }

    // CLOUDFLARE API ENDPOINTS
    if ($_GET['api'] === 'cf_get_zones') {
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';
        $res = CloudflareAPI::getZones($apiKey, $apiEmail);
        echo json_encode($res);
        exit;
    }

    if ($_GET['api'] === 'cf_get_zone_status') {
        $zoneId = $_GET['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';
        
        if (empty($zoneId)) {
            echo json_encode(['success' => false, 'errors' => [['message' => 'Zone ID belum dipilih']]]);
            exit;
        }

        $secRes = CloudflareAPI::getSecurityLevel($zoneId, $apiKey, $apiEmail);
        $rulesRes = CloudflareAPI::getIpAccessRules($zoneId, $apiKey, $apiEmail);

        echo json_encode([
            'success' => true,
            'security_level' => $secRes['result']['value'] ?? 'unknown',
            'rules' => $rulesRes['result'] ?? []
        ]);
        exit;
    }

    if ($_GET['api'] === 'cf_set_security_level') {
        $data = json_decode(file_get_contents('php://input'), true);
        $zoneId = $data['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $level = $data['level'] ?? 'medium';
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';

        $res = CloudflareAPI::setSecurityLevel($zoneId, $level, $apiKey, $apiEmail);
        echo json_encode($res);
        exit;
    }

    if ($_GET['api'] === 'cf_block_ip') {
        $data = json_decode(file_get_contents('php://input'), true);
        $zoneId = $data['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $ip = trim($data['ip'] ?? '');
        $mode = $data['mode'] ?? 'block';
        $notes = $data['notes'] ?? 'Manual block via Panel';
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';

        if (empty($ip)) {
            echo json_encode(['success' => false, 'errors' => [['message' => 'IP address tidak boleh kosong']]]);
            exit;
        }

        $res = CloudflareAPI::blockIpOnCloudflare($zoneId, $ip, $mode, $notes, $apiKey, $apiEmail);
        echo json_encode($res);
        exit;
    }

    if ($_GET['api'] === 'cf_delete_rule') {
        $data = json_decode(file_get_contents('php://input'), true);
        $zoneId = $data['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $ruleId = $data['rule_id'] ?? '';
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';

        $res = CloudflareAPI::deleteIpAccessRule($zoneId, $ruleId, $apiKey, $apiEmail);
        echo json_encode($res);
        exit;
    }

    if ($_GET['api'] === 'cf_purge_cache') {
        $data = json_decode(file_get_contents('php://input'), true);
        $zoneId = $data['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';

        $res = CloudflareAPI::purgeCache($zoneId, $apiKey, $apiEmail);
        echo json_encode($res);
        exit;
    }

    // CLOUDFLARE ZERO TRUST ACCESS APIS
    if ($_GET['api'] === 'cf_get_access_apps') {
        $zoneId = $_GET['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';

        if (empty($zoneId)) {
            echo json_encode(['success' => false, 'errors' => [['message' => 'Zone ID belum dipilih']]]);
            exit;
        }

        $res = CloudflareAPI::getAccessApps($zoneId, $apiKey, $apiEmail);
        echo json_encode($res);
        exit;
    }

    if ($_GET['api'] === 'cf_create_access_app') {
        $data = json_decode(file_get_contents('php://input'), true);
        $zoneId = $data['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $name = trim($data['name'] ?? '');
        $domain = trim($data['domain'] ?? '');
        $sessionDuration = $data['session_duration'] ?? '24h';
        $policyName = trim($data['policy_name'] ?? 'Allow Authorized Emails');
        $emails = explode(',', $data['emails'] ?? '');
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';

        if (empty($zoneId) || empty($name) || empty($domain)) {
            echo json_encode(['success' => false, 'errors' => [['message' => 'Zone ID, Nama App, dan Domain wajib diisi']]]);
            exit;
        }

        $appRes = CloudflareAPI::createAccessApp($zoneId, $name, $domain, $sessionDuration, $apiKey, $apiEmail);
        if (empty($appRes['success']) || empty($appRes['result']['id'])) {
            echo json_encode($appRes);
            exit;
        }

        $appId = $appRes['result']['id'];
        $policyRes = CloudflareAPI::createAccessPolicy($zoneId, $appId, $policyName, 'allow', $emails, $apiKey, $apiEmail);

        echo json_encode([
            'success' => true,
            'result' => $appRes['result'],
            'policy' => $policyRes['result'] ?? null
        ]);
        exit;
    }

    if ($_GET['api'] === 'cf_delete_access_app') {
        $data = json_decode(file_get_contents('php://input'), true);
        $zoneId = $data['zone_id'] ?? $settings['cf_default_zone_id'] ?? '';
        $appId = $data['app_id'] ?? '';
        $apiKey = $settings['cf_api_key'] ?? '';
        $apiEmail = $settings['cf_api_email'] ?? '';

        $res = CloudflareAPI::deleteAccessApp($zoneId, $appId, $apiKey, $apiEmail);
        echo json_encode($res);
        exit;
    }

    if ($_GET['api'] === 'save_settings') {
        $data = json_decode(file_get_contents('php://input'), true);
        $keys = [
            'global_client_rate', 'global_client_burst', 'global_conn_limit', 
            'fail2ban_bantime', 'fail2ban_findtime', 'fail2ban_maxretry',
            'block_bad_bots', 'block_hidden_files',
            'cf_api_key', 'cf_api_email', 'cf_default_zone_id',
            'cf_auto_sync_ban', 'cf_auto_ban_mode'
        ];
        foreach ($keys as $k) {
            if (isset($data[$k])) {
                $stmt = $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
                $stmt->execute([$k, $data[$k]]);
            }
        }
        if (!empty($data['new_password'])) {
            $stmt = $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
            $stmt->execute(['admin_password', password_hash($data['new_password'], PASSWORD_BCRYPT)]);
        }

        $syncRes = PanelEngine::syncNginx();
        echo json_encode($syncRes);
        exit;
    }

    if ($_GET['api'] === 'save_domain') {
        $data = json_decode(file_get_contents('php://input'), true);
        $id = !empty($data['id']) ? intval($data['id']) : 0;
        $domain = trim($data['domain'] ?? '');
        $targetType = $data['target_type'] ?? 'local_php';
        $targetValue = trim($data['target_value'] ?? '');
        $isWildcard = !empty($data['is_wildcard']) ? 1 : 0;
        $cfZoneId = trim($data['cf_zone_id'] ?? '');
        $customRate = intval($data['custom_rate_limit'] ?? 0);
        $customBurst = intval($data['custom_rate_burst'] ?? 0);
        $customConn = intval($data['custom_conn_limit'] ?? 0);
        $requireZtAccess = !empty($data['require_zt_access']) ? 1 : 0;
        $geoipMode = $data['geoip_mode'] ?? 'off';
        $geoipCountries = strtoupper(trim($data['geoip_countries'] ?? ''));
        $status = isset($data['status']) ? intval($data['status']) : 1;

        if (empty($domain)) {
            echo json_encode(['status' => false, 'message' => 'Domain tidak boleh kosong']);
            exit;
        }

        if ($targetType === 'local_php' && empty($targetValue)) {
            $targetValue = '/var/www/html';
        }

        if ($id > 0) {
            $stmt = $db->prepare("UPDATE domains SET domain=?, target_type=?, target_value=?, is_wildcard=?, cf_zone_id=?, custom_rate_limit=?, custom_rate_burst=?, custom_conn_limit=?, require_zt_access=?, geoip_mode=?, geoip_countries=?, status=? WHERE id=?");
            $stmt->execute([$domain, $targetType, $targetValue, $isWildcard, $cfZoneId, $customRate, $customBurst, $customConn, $requireZtAccess, $geoipMode, $geoipCountries, $status, $id]);
        } else {
            $stmt = $db->prepare("INSERT INTO domains (domain, target_type, target_value, is_wildcard, cf_zone_id, custom_rate_limit, custom_rate_burst, custom_conn_limit, require_zt_access, geoip_mode, geoip_countries, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$domain, $targetType, $targetValue, $isWildcard, $cfZoneId, $customRate, $customBurst, $customConn, $requireZtAccess, $geoipMode, $geoipCountries, $status]);
        }

        $syncRes = PanelEngine::syncNginx();
        echo json_encode($syncRes);
        exit;
    }

    if ($_GET['api'] === 'delete_domain') {
        $data = json_decode(file_get_contents('php://input'), true);
        $id = intval($data['id'] ?? 0);
        $stmt = $db->prepare("DELETE FROM domains WHERE id = ?");
        $stmt->execute([$id]);

        $syncRes = PanelEngine::syncNginx();
        echo json_encode($syncRes);
        exit;
    }

    if ($_GET['api'] === 'unban_ip') {
        $data = json_decode(file_get_contents('php://input'), true);
        $ip = escapeshellarg($data['ip'] ?? '');
        $jail = escapeshellarg($data['jail'] ?? '');
        $rawIp = trim($data['ip'] ?? '');
        
        $out = '';
        if (!empty($data['jail'])) {
            $out = shell_exec("sudo fail2ban-client set {$jail} unbanip {$ip} 2>&1");
        } else {
            $out = shell_exec("sudo fail2ban-client unban {$ip} 2>&1");
        }
        
        // Ensure Nginx block is removed & Cloudflare is synced
        if (!empty($rawIp)) {
            shell_exec("sudo /usr/local/bin/f2b-nginx-block.sh unban " . escapeshellarg($rawIp) . " 2>&1");
            shell_exec("sudo ufw delete reject from " . escapeshellarg($rawIp) . " 2>&1");
            shell_exec("sudo ufw delete deny from " . escapeshellarg($rawIp) . " 2>&1");
        }

        echo json_encode(['status' => true, 'message' => trim($out ?: 'IP berhasil di-unban')]);
        exit;
    }

    exit;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anti-DDoS & Proxy Guard Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; }
        .log-terminal { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.78rem; line-height: 1.4; }
    </style>
</head>
<body class="min-h-screen flex flex-col">

<?php if (!$isLoggedIn): ?>
<!-- LOGIN SCREEN -->
<div class="flex-1 flex items-center justify-center p-4">
    <div class="card p-8 w-full max-w-md shadow-2xl">
        <div class="text-center mb-6">
            <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-600/20 text-blue-500 mb-3 text-3xl">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <h1 class="text-2xl font-bold text-white tracking-wide">Anti-DDoS Panel</h1>
            <p class="text-sm text-slate-400 mt-1">Zerif High-Protection Reverse Proxy</p>
        </div>
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="mb-4">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">Password Admin</label>
                <div class="relative">
                    <input type="password" id="loginPassword" class="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:outline-none focus:border-blue-500 text-white" placeholder="Masukkan password (default: admin123)" required>
                </div>
            </div>
            <div id="loginError" class="hidden mb-4 p-3 bg-red-900/40 border border-red-700 text-red-300 rounded text-sm"></div>
            <button type="submit" class="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg shadow-lg transition duration-200">
                Masuk ke Panel <i class="fa-solid fa-arrow-right ml-1"></i>
            </button>
        </form>
    </div>
</div>

<script>
async function handleLogin(e) {
    e.preventDefault();
    const pass = document.getElementById('loginPassword').value;
    const btn = e.target.querySelector('button');
    btn.disabled = true;
    btn.innerText = 'Memverifikasi...';
    try {
        const res = await fetch('?api=login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({password: pass})
        });
        const json = await res.json();
        if (json.status) {
            window.location.reload();
        } else {
            document.getElementById('loginError').innerText = json.message || 'Login gagal';
            document.getElementById('loginError').classList.remove('hidden');
            btn.disabled = false;
            btn.innerText = 'Masuk ke Panel';
        }
    } catch (err) {
        alert('Gagal menghubungi server');
        btn.disabled = false;
    }
}
</script>

<?php else: ?>
<!-- DASHBOARD SCREEN -->
<nav class="bg-slate-900 border-b border-slate-800 px-6 py-4 flex flex-wrap items-center justify-between sticky top-0 z-50 gap-3">
    <div class="flex items-center space-x-3">
        <span class="text-blue-500 text-2xl"><i class="fa-solid fa-shield-halved"></i></span>
        <div>
            <h1 class="font-bold text-lg text-white leading-tight">Anti-DDoS & Proxy Guard</h1>
            <span class="text-xs text-slate-400">PHP 8.3 & Cloudflare Full Suite Protection</span>
        </div>
    </div>
    <div class="flex items-center flex-wrap gap-2">
        <button onclick="openTab('domains')" class="px-3 py-1.5 rounded-md text-sm font-medium hover:bg-slate-800 text-slate-300 tab-btn" id="tab-btn-domains"><i class="fa-solid fa-globe mr-1.5"></i>Domains</button>
        <button onclick="openTab('security')" class="px-3 py-1.5 rounded-md text-sm font-medium hover:bg-slate-800 text-slate-300 tab-btn" id="tab-btn-security"><i class="fa-solid fa-gauge-high mr-1.5"></i>Local Limits & Ban</button>
        <button onclick="openTab('cloudflare')" class="px-3 py-1.5 rounded-md text-sm font-medium hover:bg-slate-800 text-slate-300 tab-btn" id="tab-btn-cloudflare"><i class="fa-brands fa-cloudflare mr-1.5 text-amber-500"></i>Cloudflare Shield & Zero Trust</button>
        <button onclick="openTab('logs')" class="px-3 py-1.5 rounded-md text-sm font-medium hover:bg-slate-800 text-slate-300 tab-btn" id="tab-btn-logs"><i class="fa-solid fa-terminal mr-1.5"></i>Live Logs</button>
        <button onclick="openTab('monitor')" class="px-3 py-1.5 rounded-md text-sm font-medium hover:bg-slate-800 text-slate-300 tab-btn" id="tab-btn-monitor"><i class="fa-solid fa-ban mr-1.5"></i>Ban Monitor</button>
        <button onclick="logout()" class="px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-md text-sm font-medium transition"><i class="fa-solid fa-power-off mr-1"></i>Logout</button>
    </div>
</nav>

<div class="p-6 max-w-7xl mx-auto w-full flex-1">
    
    <!-- SYSTEM HEALTH BAR -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="card p-4 flex items-center justify-between">
            <div>
                <p class="text-xs text-slate-400 uppercase font-bold tracking-wider">Nginx Engine</p>
                <h3 class="text-xl font-bold text-white mt-1" id="sysNginx"><span class="animate-pulse">Checking...</span></h3>
            </div>
            <div class="w-10 h-10 rounded-full bg-emerald-500/10 flex items-center justify-center text-emerald-400 text-xl"><i class="fa-solid fa-server"></i></div>
        </div>
        <div class="card p-4 flex items-center justify-between">
            <div>
                <p class="text-xs text-slate-400 uppercase font-bold tracking-wider">PHP 8.3 FPM</p>
                <h3 class="text-xl font-bold text-white mt-1" id="sysPhp"><span class="animate-pulse">Checking...</span></h3>
            </div>
            <div class="w-10 h-10 rounded-full bg-blue-500/10 flex items-center justify-center text-blue-400 text-xl"><i class="fa-brands fa-php"></i></div>
        </div>
        <div class="card p-4 flex items-center justify-between">
            <div>
                <p class="text-xs text-slate-400 uppercase font-bold tracking-wider">Fail2ban Defense</p>
                <h3 class="text-xl font-bold text-white mt-1" id="sysFail2ban"><span class="animate-pulse">Checking...</span></h3>
            </div>
            <div class="w-10 h-10 rounded-full bg-indigo-500/10 flex items-center justify-center text-indigo-400 text-xl"><i class="fa-solid fa-shield"></i></div>
        </div>
        <div class="card p-4 flex items-center justify-between">
            <div>
                <p class="text-xs text-slate-400 uppercase font-bold tracking-wider">Cloudflare Edge Shield</p>
                <h3 class="text-xl font-bold text-white mt-1" id="sysCfStatus"><span class="text-slate-500 text-sm">Not Configured</span></h3>
            </div>
            <div class="w-10 h-10 rounded-full bg-amber-500/10 flex items-center justify-center text-amber-500 text-xl"><i class="fa-brands fa-cloudflare"></i></div>
        </div>
    </div>

    <!-- TAB 1: DOMAINS & FORWARDING -->
    <div id="tab-domains" class="tab-content">
        <div class="flex items-center justify-between mb-4">
            <div>
                <h2 class="text-xl font-bold text-white">Domain & Proxy Routing</h2>
                <p class="text-sm text-slate-400">Atur domain, forward proxy, local PHP handler, wildcard, dan Zero Trust guard</p>
            </div>
            <button onclick="openDomainModal()" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium text-sm shadow-md transition">
                <i class="fa-solid fa-plus mr-1.5"></i>Tambah Domain
            </button>
        </div>

        <div class="card overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-800/60 border-b border-slate-700 text-xs font-semibold uppercase text-slate-400 tracking-wider">
                            <th class="p-4">Domain / Wildcard</th>
                            <th class="p-4">Target Type</th>
                            <th class="p-4">Destination</th>
                            <th class="p-4">Per-IP Rate Limit</th>
                            <th class="p-4">Zero Trust Auth</th>
                            <th class="p-4">Status</th>
                            <th class="p-4 text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody id="domainTableBody" class="divide-y divide-slate-800 text-sm">
                        <tr><td colspan="7" class="p-8 text-center text-slate-500">Memuat data domain...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TAB 2: LOCAL SECURITY & RATE LIMITS -->
    <div id="tab-security" class="tab-content hidden">
        <div class="mb-4">
            <h2 class="text-xl font-bold text-white">Rate Limiting & Ban Duration Settings</h2>
            <p class="text-sm text-slate-400">Atur batasan request global, burst capacity, dan durasi hukuman ban IP otomatis</p>
        </div>

        <form id="settingsForm" onsubmit="saveSettings(event)" class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="card p-6">
                <h3 class="font-bold text-white text-base mb-4 flex items-center text-blue-400"><i class="fa-solid fa-sliders mr-2"></i>Global Rate Limit (Per IP)</h3>
                
                <div class="mb-4">
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Global Rate Limit per IP (Contoh: 10r/s atau 100r/m)</label>
                    <input type="text" id="setting_global_client_rate" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" placeholder="10r/s">
                    <span class="text-xs text-slate-400 mt-1 block">Format: `10r/s` (10 req per detik) atau `100r/m` (100 req per menit).</span>
                </div>

                <div class="mb-4">
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Burst Queue Capacity (Toleransi lonjakan sebelum drop)</label>
                    <input type="number" id="setting_global_client_burst" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" placeholder="20">
                    <span class="text-xs text-slate-400 mt-1 block">Jumlah request yang ditampung sesaat sebelum request di-drop.</span>
                </div>

                <div class="mb-4">
                    <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Max Concurrent Connections per IP</label>
                    <input type="number" id="setting_global_conn_limit" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" placeholder="25">
                    <span class="text-xs text-slate-400 mt-1 block">Mencegah serangan HTTP Slowloris / TCP connection flood.</span>
                </div>

                <!-- FAIL2BAN BAN TIME DURATION SETTING -->
                <div class="pt-4 border-t border-slate-800">
                    <h4 class="font-bold text-sm text-red-400 mb-3 flex items-center"><i class="fa-solid fa-stopwatch mr-1.5"></i>Fail2ban Auto-Ban Duration</h4>
                    
                    <div class="grid grid-cols-2 gap-3 mb-3">
                        <div>
                            <label class="block text-xs text-slate-300 mb-1">Waktu / Durasi Ban (Bantime)</label>
                            <input type="text" id="setting_fail2ban_bantime" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono text-sm" placeholder="10m">
                            <span class="text-[11px] text-slate-400 mt-0.5 block">Contoh: `10m` (10 menit), `1h` (1 jam), `24h` (1 hari).</span>
                        </div>
                        <div>
                            <label class="block text-xs text-slate-300 mb-1">Jendela Deteksi (Findtime)</label>
                            <input type="text" id="setting_fail2ban_findtime" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono text-sm" placeholder="1m">
                            <span class="text-[11px] text-slate-400 mt-0.5 block">Rentang waktu pelanggaran dihitung (contoh: `1m`).</span>
                        </div>
                    </div>

                    <div>
                        <label class="block text-xs text-slate-300 mb-1">Maksimal Pelanggaran Rate Limit (Max Retry)</label>
                        <input type="number" id="setting_fail2ban_maxretry" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono text-sm" placeholder="5">
                        <span class="text-[11px] text-slate-400 mt-0.5 block">Jika IP terkena rate limit sebanyak angka ini dalam jendela deteksi, IP langsung di-ban sesuai durasi di atas.</span>
                    </div>
                </div>
            </div>

            <div class="card p-6 flex flex-col justify-between">
                <div>
                    <h3 class="font-bold text-white text-base mb-4 flex items-center text-emerald-400"><i class="fa-solid fa-shield-virus mr-2"></i>Automated Shield & Whitelist</h3>
                    
                    <div class="space-y-4">
                        <label class="flex items-start space-x-3 cursor-pointer p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                            <input type="checkbox" id="setting_block_bad_bots" class="mt-1 w-4 h-4 text-blue-600 rounded bg-slate-800 border-slate-700">
                            <div>
                                <span class="font-medium text-white text-sm block">Auto-Block Vulnerability Scanners</span>
                                <span class="text-xs text-slate-400">Blokir otomatis bot seperti sqlmap, nikto, gobuster, nmap, masscan.</span>
                            </div>
                        </label>

                        <label class="flex items-start space-x-3 cursor-pointer p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                            <input type="checkbox" id="setting_block_hidden_files" class="mt-1 w-4 h-4 text-blue-600 rounded bg-slate-800 border-slate-700">
                            <div>
                                <span class="font-medium text-white text-sm block">Shield Sensitive Files</span>
                                <span class="text-xs text-slate-400">Blokir akses publik ke `.env`, `.git`, `.sql`, `.bak`, `.log`, `.yml`.</span>
                            </div>
                        </label>

                        <div class="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                            <span class="font-medium text-amber-400 text-sm block"><i class="fa-solid fa-lock mr-1"></i>Whitelist Anti-Terkunci</span>
                            <span class="text-xs text-slate-400 block mt-0.5">IP Local (`127.0.0.1`), Subnet LAN (`192.168.x.x`), dan Tailscale (`100.64.0.0/10`) otomatis di-whitelist dari Fail2ban & ban rules.</span>
                        </div>

                        <!-- AUTO-DEPLOY TO CLOUDFLARE WAF -->
                        <div class="p-4 bg-amber-950/20 border border-amber-500/30 rounded-xl space-y-3">
                            <label class="flex items-start space-x-3 cursor-pointer">
                                <input type="checkbox" id="setting_cf_auto_sync_ban" class="mt-1 w-4 h-4 text-amber-500 rounded bg-slate-800 border-slate-700">
                                <div>
                                    <span class="font-bold text-amber-400 text-sm block"><i class="fa-brands fa-cloudflare mr-1.5 text-base"></i>Auto-Deploy Banned IP ke Cloudflare Edge WAF</span>
                                    <span class="text-xs text-slate-400 block mt-0.5">Setiap kali penyerang melanggar rate limit / ter-ban oleh Fail2ban, IP penyerang otomatis langsung didaftarkan ke Cloudflare WAF sehingga dicegat di server Cloudflare sebelum menyentuh server kamu.</span>
                                </div>
                            </label>
                            <div class="pl-7">
                                <label class="block text-xs font-semibold text-slate-300 mb-1">Mode Eksekusi di Cloudflare Edge</label>
                                <select id="setting_cf_auto_ban_mode" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-xs focus:outline-none">
                                    <option value="block">🚫 Block (Tolak Total 403 di Edge Cloudflare)</option>
                                    <option value="challenge">🧩 Managed Challenge (Wajib Selesaikan Captcha)</option>
                                    <option value="js_challenge">⚡ JS Challenge (Interactive Browser Check)</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="mt-6 pt-4 border-t border-slate-800">
                    <div class="mb-4">
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Ganti Password Admin (Opsional)</label>
                        <input type="password" id="setting_new_password" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" placeholder="Biarkan kosong jika tidak diganti">
                    </div>
                    <button type="submit" class="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg shadow-md transition">
                        <i class="fa-solid fa-check mr-1.5"></i>Terapkan & Reload Nginx + Fail2ban
                    </button>
                </div>
            </div>
        </form>
    </div>

    <!-- TAB 3: CLOUDFLARE SHIELD & ZERO TRUST UNIFIED -->
    <div id="tab-cloudflare" class="tab-content hidden">
        
        <!-- TOP CONTROL BAR: UNIFIED ZONE SELECTOR & CREDENTIALS -->
        <div class="card p-6 mb-6">
            <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5 mb-5">
                <div>
                    <h2 class="text-xl font-bold text-white flex items-center">
                        <i class="fa-brands fa-cloudflare text-amber-500 mr-2 text-2xl"></i>Cloudflare Unified Shield & Zero Trust
                    </h2>
                    <p class="text-sm text-slate-400">Pusat kendali proteksi Edge Cloudflare, IP WAF Firewall, Under Attack Mode, dan Zero Trust Access</p>
                </div>
                
                <!-- ZONE SELECTOR (GLOBAL FOR THIS TAB) -->
                <div class="flex items-center space-x-2 bg-slate-900 p-2 rounded-xl border border-amber-500/30">
                    <span class="text-xs font-bold text-amber-400 uppercase tracking-wider pl-2"><i class="fa-solid fa-globe mr-1.5"></i>Active Zone:</span>
                    <select id="cf_zone_selector" onchange="onZoneChanged()" class="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-white text-sm font-semibold focus:outline-none min-w-[200px]">
                        <option value="">-- Pilih Domain / Zone --</option>
                    </select>
                    <button onclick="fetchCfZones()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm transition" title="Tarik / Refresh daftar domain dari Cloudflare">
                        <i class="fa-solid fa-sync"></i>
                    </button>
                    <button onclick="purgeCfCache()" class="px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/40 text-amber-300 border border-amber-500/30 rounded-lg text-xs font-semibold transition" title="Bersihkan cache domain ini">
                        <i class="fa-solid fa-broom mr-1"></i>Purge Cache
                    </button>
                </div>
            </div>

            <!-- API CREDENTIALS FORM (COLLAPSIBLE / COMPACT) -->
            <div>
                <h3 class="font-bold text-white text-sm mb-3 flex items-center text-slate-300">
                    <i class="fa-solid fa-key mr-2 text-amber-400"></i>Cloudflare API Credentials
                </h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Cloudflare API Token / Global Key</label>
                        <input type="password" id="cf_api_key" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono text-sm" placeholder="Paste API Token atau Global Key">
                        <span class="text-[11px] text-slate-400 mt-1 block">Token Permissions: Zone Read, Zone Settings Edit, Firewall Edit, Access Apps/Policies Edit.</span>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Cloudflare Email (Kosongkan jika pakai API Token)</label>
                        <input type="email" id="cf_api_email" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm" placeholder="Kosongkan jika pakai API Token">
                        <span class="text-[11px] text-slate-400 mt-1 block">Hanya diisi jika kamu memakai Global API Key.</span>
                    </div>
                    <div class="flex items-end">
                        <button onclick="saveCfCredentials()" class="w-full py-2.5 bg-amber-600 hover:bg-amber-500 text-white font-semibold rounded-lg text-sm shadow-md transition">
                            <i class="fa-solid fa-floppy-disk mr-1.5"></i>Simpan Kredensial Cloudflare
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- SECTION 1: EDGE SECURITY & IP WAF BLOCKER -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <!-- Left: Attack Mode & Security Level -->
            <div class="card p-6 flex flex-col justify-between">
                <div>
                    <h3 class="font-bold text-white text-base mb-3 flex items-center text-red-400">
                        <i class="fa-solid fa-bolt mr-2"></i>Emergency Defense
                    </h3>
                    <p class="text-xs text-slate-400 mb-4">Jika domain aktif sedang diserang habis-habisan, aktifkan <b>Under Attack Mode</b> untuk mengaktifkan challenge JS/Captcha di seluruh pengunjung di level Cloudflare.</p>
                    
                    <div class="p-4 bg-slate-900/80 rounded-xl border border-slate-700/60 mb-4 text-center">
                        <span class="text-xs text-slate-400 uppercase font-bold tracking-wider block mb-1">Security Level Saat Ini:</span>
                        <span id="currentCfSecLevel" class="text-lg font-bold text-amber-400 uppercase tracking-wide">Pilih Domain</span>
                    </div>

                    <div class="space-y-2">
                        <button onclick="setCfSecurityLevel('under_attack')" class="w-full py-2.5 bg-red-600 hover:bg-red-500 text-white font-bold rounded-lg shadow-lg transition flex items-center justify-center">
                            <i class="fa-solid fa-radiation mr-2"></i>🔥 I'M UNDER ATTACK (Max)
                        </button>
                        <button onclick="setCfSecurityLevel('high')" class="w-full py-2 bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 border border-amber-600/40 font-semibold rounded-lg transition">
                            High Security (Challenge suspect)
                        </button>
                        <button onclick="setCfSecurityLevel('medium')" class="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded-lg transition">
                            Medium (Standar Normal)
                        </button>
                    </div>
                </div>
            </div>

            <!-- Right: Direct Cloudflare IP Blocker -->
            <div class="md:col-span-2 card p-6">
                <h3 class="font-bold text-white text-base mb-2 flex items-center text-blue-400">
                    <i class="fa-solid fa-ban mr-2"></i>Blokir IP di Cloudflare Edge WAF
                </h3>
                <p class="text-xs text-slate-400 mb-4">IP yang dimasukkan akan di-drop langsung oleh Cloudflare sehingga serangan <b>sama sekali tidak pernah sampai ke server / kuota kamu</b>.</p>

                <form id="cfBlockForm" onsubmit="blockIpCloudflare(event)" class="grid grid-cols-1 sm:grid-cols-4 gap-3 mb-6 bg-slate-900/60 p-4 rounded-xl border border-slate-800">
                    <div class="sm:col-span-2">
                        <label class="block text-xs font-semibold text-slate-300 mb-1">IP Target (IPv4 / IPv6 / Subnet)</label>
                        <input type="text" id="cf_block_ip_input" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-white font-mono text-sm" placeholder="Contoh: 182.8.179.104" required>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-300 mb-1">Aksi</label>
                        <select id="cf_block_mode_input" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-white text-sm">
                            <option value="block">🚫 Block (Tolak Total)</option>
                            <option value="challenge">🧩 Managed Challenge (Captcha)</option>
                            <option value="js_challenge">⚡ JS Challenge</option>
                            <option value="whitelist">✅ Whitelist (Lewatkan)</option>
                        </select>
                    </div>
                    <div class="flex items-end">
                        <button type="submit" class="w-full py-2 bg-red-600 hover:bg-red-500 text-white font-semibold rounded-lg text-sm shadow-md transition" id="btnBlockCf">
                            <i class="fa-solid fa-shield-virus mr-1"></i>Eksekusi IP
                        </button>
                    </div>
                </form>

                <!-- Active Cloudflare Rules Table -->
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse text-sm">
                        <thead>
                            <tr class="bg-slate-900 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                                <th class="p-3">IP / Target</th>
                                <th class="p-3">Aksi Cloudflare</th>
                                <th class="p-3">Catatan</th>
                                <th class="p-3 text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody id="cfRulesTableBody" class="divide-y divide-slate-800">
                            <tr><td colspan="4" class="p-6 text-center text-slate-500">Pilih Zone ID untuk melihat daftar IP yang diblokir.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- SECTION 2: ZERO TRUST ACCESS CONTROL (INTEGRATED) -->
        <div class="card p-6">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-4">
                <div>
                    <h3 class="font-bold text-white text-base flex items-center">
                        <i class="fa-solid fa-user-lock text-purple-400 mr-2"></i>Cloudflare Zero Trust Access Control
                    </h3>
                    <p class="text-xs text-slate-400 mt-0.5">Kunci web/subdomain di Zone terpilih dengan proteksi OTP Email, Google, atau GitHub</p>
                </div>
                <button onclick="openCreateAccessModal()" class="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg font-medium text-sm shadow-md transition">
                    <i class="fa-solid fa-plus mr-1.5"></i>Buat Zero Trust App Baru
                </button>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-5">
                <div class="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl flex items-center space-x-3">
                    <div class="w-8 h-8 rounded-lg bg-purple-500/20 text-purple-300 flex items-center justify-center font-bold text-sm"><i class="fa-solid fa-shield-cat"></i></div>
                    <div>
                        <h4 class="font-bold text-white text-xs">Edge Identity Gate</h4>
                        <p class="text-[11px] text-slate-400">Bot DDoS tertahan 100% di server Cloudflare.</p>
                    </div>
                </div>
                <div class="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl flex items-center space-x-3">
                    <div class="w-8 h-8 rounded-lg bg-blue-500/20 text-blue-300 flex items-center justify-center font-bold text-sm"><i class="fa-solid fa-envelope-circle-check"></i></div>
                    <div>
                        <h4 class="font-bold text-white text-xs">Email Whitelist (OTP)</h4>
                        <p class="text-[11px] text-slate-400">Hanya email terdaftar yang bisa meminta kode login PIN.</p>
                    </div>
                </div>
                <div class="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl flex items-center space-x-3">
                    <div class="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-300 flex items-center justify-center font-bold text-sm"><i class="fa-solid fa-file-shield"></i></div>
                    <div>
                        <h4 class="font-bold text-white text-xs">Nginx Token Lock</h4>
                        <p class="text-[11px] text-slate-400">Nginx server menolak setiap request tanpa JWT assertion.</p>
                    </div>
                </div>
            </div>

            <!-- ZERO TRUST APPS TABLE -->
            <div class="overflow-x-auto border border-slate-800 rounded-xl">
                <table class="w-full text-left border-collapse text-sm">
                    <thead>
                        <tr class="bg-slate-900 border-b border-slate-800 text-xs font-semibold uppercase text-slate-400">
                            <th class="p-3.5">Nama Aplikasi</th>
                            <th class="p-3.5">Protected Domain / URL</th>
                            <th class="p-3.5">Session Duration</th>
                            <th class="p-3.5">App ID</th>
                            <th class="p-3.5 text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody id="ztAppsTableBody" class="divide-y divide-slate-800">
                        <tr><td colspan="5" class="p-6 text-center text-slate-500">Pilih Zone ID di atas untuk memuat aplikasi Zero Trust.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TAB 4: LIVE ACCESS LOGS -->
    <div id="tab-logs" class="tab-content hidden">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
            <div>
                <h2 class="text-xl font-bold text-white flex items-center">
                    <i class="fa-solid fa-terminal mr-2 text-blue-400"></i>Live Traffic & DDoS Attack Logs
                </h2>
                <p class="text-sm text-slate-400">Pantau request real-time pengunjung dan deteksi rate limit / serangan</p>
            </div>
            <div class="flex items-center space-x-2">
                <select id="logTypeSelect" onchange="fetchLogs()" class="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white focus:outline-none">
                    <option value="access">Access Logs (Semua Traffic)</option>
                    <option value="ddos">DDoS / Rate Limiting Drops</option>
                    <option value="error">Nginx Error Logs</option>
                </select>
                <input type="text" id="logFilterInput" onkeyup="filterLogs()" placeholder="Cari IP / Domain / Status..." class="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-sm text-white focus:outline-none">
                <button onclick="fetchLogs()" class="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition">
                    <i class="fa-solid fa-rotate-right mr-1"></i>Refresh
                </button>
                <button onclick="clearLogs()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-red-400 rounded-lg text-sm font-medium transition" title="Bersihkan file log">
                    <i class="fa-solid fa-trash"></i>
                </button>
            </div>
        </div>

        <div class="card p-4 overflow-hidden">
            <div class="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-xs text-slate-400">
                <span id="logSummary">Memuat log...</span>
                <span class="flex items-center"><span class="w-2 h-2 rounded-full bg-emerald-400 inline-block mr-1.5 animate-pulse"></span>Live Polling Aktif (tiap 5s)</span>
            </div>
            <div id="logContainer" class="log-terminal bg-slate-950 p-4 rounded-lg overflow-x-auto overflow-y-auto max-h-[600px] border border-slate-800/80 text-slate-300 space-y-1">
                <div class="text-slate-500 italic">Mengambil data log terbaru...</div>
            </div>
        </div>
    </div>

    <!-- TAB 5: BAN MONITOR -->
    <div id="tab-monitor" class="tab-content hidden">
        <div class="flex items-center justify-between mb-4">
            <div>
                <h2 class="text-xl font-bold text-white">Live Ban & Attack Monitor</h2>
                <p class="text-sm text-slate-400">Daftar IP yang diblokir otomatis oleh Fail2ban karena melanggar threshold</p>
            </div>
            <button onclick="loadDashboardData()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-md text-xs font-medium">
                <i class="fa-solid fa-rotate-right mr-1"></i>Refresh
            </button>
        </div>

        <div class="card overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-800/60 border-b border-slate-700 text-xs font-semibold uppercase text-slate-400 tracking-wider">
                            <th class="p-4">IP Address</th>
                            <th class="p-4">Jail / Trigger</th>
                            <th class="p-4">Action</th>
                        </tr>
                    </thead>
                    <tbody id="bannedTableBody" class="divide-y divide-slate-800 text-sm">
                        <tr><td colspan="3" class="p-8 text-center text-slate-500">Tidak ada IP yang sedang ter-ban. Semua aman!</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- MODAL ADD/EDIT DOMAIN -->
<div id="domainModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden overflow-y-auto flex items-center justify-center p-4 py-8">
    <div class="card p-6 w-full max-w-xl shadow-2xl my-auto max-h-[90vh] overflow-y-auto">
        <div class="flex items-center justify-between border-b border-slate-700 pb-3 mb-4">
            <h3 class="font-bold text-white text-lg" id="modalTitle">Tambah Konfigurasi Domain</h3>
            <button onclick="closeDomainModal()" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark text-xl"></i></button>
        </div>

        <form id="domainForm" onsubmit="saveDomain(event)">
            <input type="hidden" id="form_domain_id" value="0">
            
            <div class="mb-4">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Domain Name</label>
                <input type="text" id="form_domain_name" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" placeholder="contoh: zerif.id atau app.domain.com" required>
            </div>

            <div class="mb-4">
                <label class="flex items-center space-x-2 cursor-pointer">
                    <input type="checkbox" id="form_is_wildcard" class="w-4 h-4 text-blue-600 rounded bg-slate-800 border-slate-700">
                    <span class="text-sm font-medium text-slate-200">Support Wildcard Subdomain (`*.domain.com`)</span>
                </label>
            </div>

            <div class="mb-4">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Target / Handling</label>
                <select id="form_target_type" onchange="toggleTargetInput()" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white">
                    <option value="local_php">Local PHP 8.3 Application (Folder di server)</option>
                    <option value="proxy">Reverse Proxy Forwarding (Forward ke IP:Port lain / App internal)</option>
                </select>
            </div>

            <div class="mb-4" id="targetValueWrapper">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1" id="targetValueLabel">Document Root Path</label>
                <input type="text" id="form_target_value" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" placeholder="/var/www/html">
                <span class="text-xs text-slate-400 mt-1 block" id="targetValueHelp">Direktori tempat file PHP / web berada di server ini.</span>
            </div>

            <!-- ZERO TRUST STRICT LOCK ENFORCEMENT -->
            <div class="p-4 bg-purple-950/30 border border-purple-900/50 rounded-lg mb-4">
                <label class="flex items-start space-x-3 cursor-pointer">
                    <input type="checkbox" id="form_require_zt_access" class="mt-1 w-4 h-4 text-purple-600 rounded bg-slate-900 border-slate-700">
                    <div>
                        <span class="font-bold text-sm text-purple-300 block"><i class="fa-solid fa-lock mr-1"></i>Enforce Strict Cloudflare Zero Trust</span>
                        <span class="text-xs text-slate-400 block mt-0.5">Jika dicentang, Nginx akan menolak (403 Forbidden) setiap pengunjung yang tidak melewati autentikasi OTP/SSO Cloudflare Zero Trust.</span>
                    </div>
                </label>
            </div>

            <!-- GEOIP COUNTRY FILTER / BLOCKER -->
            <div class="p-4 bg-emerald-950/20 border border-emerald-900/40 rounded-lg mb-4">
                <span class="font-bold text-sm text-emerald-400 block mb-2"><i class="fa-solid fa-earth-americas mr-1"></i>GeoIP Country Blocker & Whitelister</span>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-2">
                    <div>
                        <label class="block text-xs text-slate-300 mb-1 font-medium">Mode Proteksi Wilayah</label>
                        <select id="form_geoip_mode" onchange="toggleGeoIpInput()" class="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded text-sm text-white">
                            <option value="off">Off (Izinkan Semua Negara)</option>
                            <option value="allow_only">Hanya Izinkan Negara Tertentu (Allow Only)</option>
                            <option value="block_only">Blokir Negara Tertentu (Block Listed)</option>
                        </select>
                    </div>
                    <div id="geoipCountriesWrapper" class="hidden">
                        <label class="block text-xs text-slate-300 mb-1 font-medium">Kode Negara (Pisahkan Koma)</label>
                        <input type="text" id="form_geoip_countries" class="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded text-sm text-white font-mono uppercase" placeholder="contoh: ID atau ID,SG,MY">
                    </div>
                </div>
                <div class="flex items-center space-x-2 text-[11px] text-slate-400">
                    <span>Preset Cepat:</span>
                    <button type="button" onclick="setGeoPreset('ID')" class="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-emerald-300 rounded border border-slate-700">🇮🇩 Hanya Indonesia (ID)</button>
                    <button type="button" onclick="setGeoPreset('ID,SG,MY')" class="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-emerald-300 rounded border border-slate-700">🌏 ASEAN (ID,SG,MY)</button>
                    <button type="button" onclick="setGeoPreset('CN,RU,US')" class="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-red-300 rounded border border-slate-700">🚫 Blokir CN,RU,US</button>
                </div>
            </div>

            <!-- CUSTOM PER-DOMAIN RATE LIMIT -->
            <div class="p-4 bg-slate-900/70 border border-slate-800 rounded-lg mb-4">
                <span class="font-bold text-sm text-blue-400 block mb-2"><i class="fa-solid fa-gauge mr-1"></i>Personal / Domain Rate Limit (Khusus Domain Ini)</span>
                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="block text-xs text-slate-300 mb-1">Limit Req/detik (Per IP)</label>
                        <input type="number" id="form_custom_rate" class="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded text-sm text-white" placeholder="0 = Ikuti Global">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-300 mb-1">Burst Capacity</label>
                        <input type="number" id="form_custom_burst" class="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded text-sm text-white" placeholder="0 = Otomatis">
                    </div>
                </div>
                <span class="text-xs text-slate-400 mt-1 block">Isi `2` jika ingin membatasi domain ini maksimal 2 request/detik per IP. Isi `0` untuk ikut limit global.</span>
            </div>

            <div class="flex justify-end space-x-3 mt-6">
                <button type="button" onclick="closeDomainModal()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm">Batal</button>
                <button type="submit" class="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg text-sm shadow-md" id="saveDomainBtn">Simpan Domain</button>
            </div>
        </form>
    </div>
</div>

<!-- MODAL CREATE ZERO TRUST APP -->
<div id="ztAppModal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden flex items-center justify-center p-4">
    <div class="card p-6 w-full max-w-lg shadow-2xl">
        <div class="flex items-center justify-between border-b border-slate-700 pb-3 mb-4">
            <h3 class="font-bold text-white text-lg flex items-center"><i class="fa-solid fa-user-shield text-purple-400 mr-2"></i>Buat Zero Trust Access App</h3>
            <button onclick="closeCreateAccessModal()" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark text-xl"></i></button>
        </div>

        <form id="ztAppForm" onsubmit="saveZtApp(event)">
            <div class="mb-4">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Nama Aplikasi</label>
                <input type="text" id="zt_form_name" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white" placeholder="contoh: Admin Panel / Internal Portal" required>
            </div>

            <div class="mb-4">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Domain Target yang Diproteksi</label>
                <input type="text" id="zt_form_domain" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono text-sm" placeholder="contoh: ddos.lorry.biz.id atau admin.zerif.id" required>
            </div>

            <div class="mb-4">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Whitelist Email / Domain (Pisahkan koma)</label>
                <textarea id="zt_form_emails" rows="2" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm" placeholder="user@gmail.com, @zerif.id, *"></textarea>
                <span class="text-xs text-slate-400 mt-1 block">Tulis email spesifik (`user@gmail.com`), akhiran domain (`@zerif.id`), atau `*` (semua email yang terdaftar di organisasi kamu).</span>
            </div>

            <div class="mb-4">
                <label class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">Masa Berlaku Sesi Login</label>
                <select id="zt_form_duration" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm">
                    <option value="24h">24 Jam</option>
                    <option value="12h">12 Jam</option>
                    <option value="7d">7 Hari</option>
                    <option value="1h">1 Jam</option>
                </select>
            </div>

            <div class="flex justify-end space-x-3 mt-6">
                <button type="button" onclick="closeCreateAccessModal()" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm">Batal</button>
                <button type="submit" class="px-5 py-2 bg-purple-600 hover:bg-purple-500 text-white font-medium rounded-lg text-sm shadow-md" id="saveZtAppBtn">Deploy Zero Trust App</button>
            </div>
        </form>
    </div>
</div>

<script>
let globalData = {};
let currentLogs = [];
let activeTab = 'domains';
let cfZones = [];
let ztApps = [];

function openTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.tab-btn').forEach(el => {
        el.classList.remove('bg-slate-800', 'text-white');
        el.classList.add('text-slate-300');
    });
    document.getElementById('tab-' + tab).classList.remove('hidden');
    const btn = document.getElementById('tab-btn-' + tab);
    if (btn) {
        btn.classList.add('bg-slate-800', 'text-white');
        btn.classList.remove('text-slate-300');
    }

    if (tab === 'logs') {
        fetchLogs();
    } else if (tab === 'cloudflare') {
        fetchCfZones();
    }
}

function toggleTargetInput() {
    const type = document.getElementById('form_target_type').value;
    const label = document.getElementById('targetValueLabel');
    const input = document.getElementById('form_target_value');
    const help = document.getElementById('targetValueHelp');

    if (type === 'local_php') {
        label.innerText = 'Document Root Path';
        input.placeholder = '/var/www/html';
        help.innerText = 'Direktori tempat file PHP / web berada di server ini.';
    } else {
        label.innerText = 'Proxy Forward Target URL';
        input.placeholder = 'http://127.0.0.1:3000 atau http://103.157.96.168:80';
        help.innerText = 'Alamat target yang akan diforward (Nginx akan meneruskan request visitor ke sini).';
    }
}

async function loadDashboardData() {
    try {
        const res = await fetch('?api=get_data');
        if (res.status === 401) {
            window.location.reload();
            return;
        }
        const json = await res.json();
        if (!json.status) return;

        globalData = json;

        // System indicators
        const sysNginxEl = document.getElementById('sysNginx');
        if (sysNginxEl) {
            sysNginxEl.innerHTML = json.system.nginx === 'active' 
                ? '<span class="text-emerald-400 text-base font-semibold"><i class="fa-solid fa-circle-check mr-1"></i>Active</span>' 
                : '<span class="text-red-400 text-base font-semibold">' + json.system.nginx + '</span>';
        }
        
        const sysPhpEl = document.getElementById('sysPhp');
        if (sysPhpEl) {
            sysPhpEl.innerHTML = json.system.php === 'active' 
                ? '<span class="text-emerald-400 text-base font-semibold"><i class="fa-solid fa-circle-check mr-1"></i>Active (8.3)</span>' 
                : '<span class="text-red-400 text-base font-semibold">' + json.system.php + '</span>';
        }

        const sysF2bEl = document.getElementById('sysFail2ban');
        if (sysF2bEl) {
            sysF2bEl.innerHTML = json.system.fail2ban === 'active' 
                ? '<span class="text-emerald-400 text-base font-semibold"><i class="fa-solid fa-shield mr-1"></i>Active</span>' 
                : '<span class="text-amber-400 text-base font-semibold">' + json.system.fail2ban + '</span>';
        }

        // Settings populate
        if (json.settings) {
            const setRate = document.getElementById('setting_global_client_rate');
            if (setRate) setRate.value = json.settings.global_client_rate || '10r/s';

            const setBurst = document.getElementById('setting_global_client_burst');
            if (setBurst) setBurst.value = json.settings.global_client_burst || '20';

            const setConn = document.getElementById('setting_global_conn_limit');
            if (setConn) setConn.value = json.settings.global_conn_limit || '25';

            const setBantime = document.getElementById('setting_fail2ban_bantime');
            if (setBantime) setBantime.value = json.settings.fail2ban_bantime || '10m';

            const setFindtime = document.getElementById('setting_fail2ban_findtime');
            if (setFindtime) setFindtime.value = json.settings.fail2ban_findtime || '1m';

            const setMaxretry = document.getElementById('setting_fail2ban_maxretry');
            if (setMaxretry) setMaxretry.value = json.settings.fail2ban_maxretry || '5';

            const setBots = document.getElementById('setting_block_bad_bots');
            if (setBots) setBots.checked = json.settings.block_bad_bots === '1';

            const setFiles = document.getElementById('setting_block_hidden_files');
            if (setFiles) setFiles.checked = json.settings.block_hidden_files === '1';

            const setCfAutoBan = document.getElementById('setting_cf_auto_sync_ban');
            if (setCfAutoBan) setCfAutoBan.checked = (json.settings.cf_auto_sync_ban ?? '1') === '1';

            const setCfAutoMode = document.getElementById('setting_cf_auto_ban_mode');
            if (setCfAutoMode && json.settings.cf_auto_ban_mode) setCfAutoMode.value = json.settings.cf_auto_ban_mode;
            
            // Cloudflare credentials
            const cfKeyEl = document.getElementById('cf_api_key');
            if (cfKeyEl && json.settings.cf_api_key) {
                cfKeyEl.value = json.settings.cf_api_key;
                const cfStat = document.getElementById('sysCfStatus');
                if (cfStat) {
                    cfStat.innerHTML = '<span class="text-emerald-400 text-base font-semibold"><i class="fa-solid fa-shield-halved mr-1"></i>Connected</span>';
                }
            }
            const cfEmailEl = document.getElementById('cf_api_email');
            if (cfEmailEl && json.settings.cf_api_email) {
                cfEmailEl.value = json.settings.cf_api_email;
            }
        }

        // Render Domains Table
        const tbody = document.getElementById('domainTableBody');
        if (tbody) {
            if (json.domains.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="p-8 text-center text-slate-500">Belum ada domain terdaftar. Klik tombol <b>Tambah Domain</b> di atas.</td></tr>';
            } else {
                tbody.innerHTML = json.domains.map(d => `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-4 font-medium text-white flex items-center space-x-2">
                            <span>${escapeHtml(d.domain)}</span>
                            ${d.is_wildcard == 1 ? '<span class="px-2 py-0.5 text-xs rounded bg-purple-500/20 text-purple-300 font-mono">*.${escapeHtml(d.domain)}</span>' : ''}
                        </td>
                        <td class="p-4">
                            <span class="px-2 py-1 text-xs rounded font-medium ${d.target_type === 'local_php' ? 'bg-blue-500/20 text-blue-300' : 'bg-amber-500/20 text-amber-300'}">
                                ${d.target_type === 'local_php' ? 'PHP 8.3 Local' : 'Reverse Proxy'}
                            </span>
                        </td>
                        <td class="p-4 text-slate-300 font-mono text-xs">${escapeHtml(d.target_value)}</td>
                        <td class="p-4 text-slate-300">
                            ${d.custom_rate_limit > 0 ? `<span class="text-amber-400 font-semibold">${d.custom_rate_limit} req/s</span>` : '<span class="text-slate-500 text-xs">Global Rule</span>'}
                        </td>
                        <td class="p-4">
                            <div class="flex flex-col space-y-1">
                                ${d.require_zt_access == 1 
                                    ? '<span class="inline-flex items-center px-2 py-0.5 text-[11px] rounded bg-purple-500/20 text-purple-300 font-medium"><i class="fa-solid fa-lock mr-1"></i>ZT OTP</span>' 
                                    : ''}
                                ${d.geoip_mode === 'allow_only' 
                                    ? `<span class="inline-flex items-center px-2 py-0.5 text-[11px] rounded bg-emerald-500/20 text-emerald-300 font-medium" title="Allow only: ${escapeHtml(d.geoip_countries || '')}"><i class="fa-solid fa-shield mr-1"></i>Only: ${escapeHtml(d.geoip_countries || '')}</span>` 
                                    : ''}
                                ${d.geoip_mode === 'block_only' 
                                    ? `<span class="inline-flex items-center px-2 py-0.5 text-[11px] rounded bg-red-500/20 text-red-300 font-medium" title="Blocked: ${escapeHtml(d.geoip_countries || '')}"><i class="fa-solid fa-ban mr-1"></i>Block: ${escapeHtml(d.geoip_countries || '')}</span>` 
                                    : ''}
                                ${(!d.require_zt_access && (!d.geoip_mode || d.geoip_mode === 'off')) ? '<span class="text-slate-500 text-xs">Default</span>' : ''}
                            </div>
                        </td>
                        <td class="p-4">
                            <span class="inline-flex items-center px-2 py-0.5 text-xs rounded ${d.status == 1 ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'}">
                                ${d.status == 1 ? 'Active' : 'Disabled'}
                            </span>
                        </td>
                        <td class="p-4 text-right space-x-2">
                            <button onclick="editDomain(${d.id})" class="text-blue-400 hover:text-blue-300 px-2 py-1 bg-slate-800 rounded"><i class="fa-solid fa-pen-to-square"></i></button>
                            <button onclick="deleteDomain(${d.id}, '${escapeHtml(d.domain)}')" class="text-red-400 hover:text-red-300 px-2 py-1 bg-slate-800 rounded"><i class="fa-solid fa-trash"></i></button>
                        </td>
                    </tr>
                `).join('');
            }
        }

        // Render Banned IPs Table
        const banBody = document.getElementById('bannedTableBody');
        if (banBody) {
            if (json.banned_ips.length === 0) {
                banBody.innerHTML = '<tr><td colspan="3" class="p-8 text-center text-slate-500">Tidak ada IP yang sedang ter-ban. Semua aman!</td></tr>';
            } else {
                banBody.innerHTML = json.banned_ips.map(b => `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-4 font-mono font-bold text-red-400">${escapeHtml(b.ip)}</td>
                        <td class="p-4 text-slate-300 text-xs font-mono">${escapeHtml(b.jail)}</td>
                        <td class="p-4 space-x-2">
                            <button onclick="unbanIp('${escapeHtml(b.ip)}', '${escapeHtml(b.jail)}')" class="px-3 py-1 bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 rounded text-xs font-medium">
                                <i class="fa-solid fa-unlock mr-1"></i>Unban Local
                            </button>
                            <button onclick="quickBlockCf('${escapeHtml(b.ip)}')" class="px-3 py-1 bg-amber-600/20 hover:bg-amber-600/40 text-amber-300 rounded text-xs font-medium">
                                <i class="fa-brands fa-cloudflare mr-1"></i>Push Block to Cloudflare
                            </button>
                        </td>
                    </tr>
                `).join('');
            }
        }

    } catch (e) {
        console.error(e);
    }
}

// CLOUDFLARE JS LOGIC
async function fetchCfZones() {
    const sel = document.getElementById('cf_zone_selector');
    if (!sel) return;
    sel.innerHTML = '<option value="">Memuat daftar Zone Cloudflare...</option>';
    try {
        const res = await fetch('?api=cf_get_zones');
        const json = await res.json();
        if (json.success && json.result) {
            cfZones = json.result;
            sel.innerHTML = '<option value="">-- Pilih Domain / Zone --</option>' + 
                cfZones.map(z => `<option value="${z.id}" ${globalData.settings?.cf_default_zone_id === z.id ? 'selected' : ''}>${z.name} (${z.status})</option>`).join('');
            
            if (sel.value) {
                loadCfZoneStatus(sel.value);
                fetchZtApps();
            }
        } else {
            sel.innerHTML = '<option value="">API Key belum valid atau belum diset</option>';
        }
    } catch (e) {
        sel.innerHTML = '<option value="">Gagal memuat Zone</option>';
    }
}

function onZoneChanged() {
    const zoneId = document.getElementById('cf_zone_selector').value;
    if (zoneId) {
        loadCfZoneStatus(zoneId);
        fetchZtApps();
    }
}

async function loadCfZoneStatus(zoneId) {
    const el = document.getElementById('currentCfSecLevel');
    if (el) el.innerText = 'Loading...';
    try {
        const res = await fetch('?api=cf_get_zone_status&zone_id=' + encodeURIComponent(zoneId));
        const json = await res.json();
        if (json.success) {
            const secLevel = json.security_level;
            if (el) {
                el.innerText = secLevel;
                if (secLevel === 'under_attack') {
                    el.className = 'text-lg font-bold text-red-400 uppercase tracking-wide animate-pulse';
                } else if (secLevel === 'high') {
                    el.className = 'text-lg font-bold text-amber-400 uppercase tracking-wide';
                } else {
                    el.className = 'text-lg font-bold text-emerald-400 uppercase tracking-wide';
                }
            }

            // Render rules table
            const tbody = document.getElementById('cfRulesTableBody');
            if (tbody) {
                if (!json.rules || json.rules.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="p-6 text-center text-slate-500">Belum ada aturan IP Firewall di Cloudflare.</td></tr>';
                } else {
                    tbody.innerHTML = json.rules.map(r => `
                        <tr class="hover:bg-slate-800/40">
                            <td class="p-3 font-mono font-bold text-slate-200">${escapeHtml(r.configuration.value)}</td>
                            <td class="p-3">
                                <span class="px-2 py-0.5 text-xs rounded font-bold uppercase ${r.mode === 'block' ? 'bg-red-500/20 text-red-300' : 'bg-amber-500/20 text-amber-300'}">${r.mode}</span>
                            </td>
                            <td class="p-3 text-xs text-slate-400">${escapeHtml(r.notes || '-')}</td>
                            <td class="p-3 text-right">
                                <button onclick="deleteCfRule('${r.id}')" class="text-red-400 hover:text-red-300 px-2 py-1 bg-slate-800 rounded text-xs"><i class="fa-solid fa-trash"></i> Hapus</button>
                            </td>
                        </tr>
                    `).join('');
                }
            }
        }
    } catch (e) {
        console.error(e);
    }
}

async function saveCfCredentials() {
    const apiKey = document.getElementById('cf_api_key').value;
    const apiEmail = document.getElementById('cf_api_email').value;
    const zoneId = document.getElementById('cf_zone_selector').value;

    const payload = {
        cf_api_key: apiKey,
        cf_api_email: apiEmail,
        cf_default_zone_id: zoneId
    };

    try {
        const res = await fetch('?api=save_settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const json = await res.json();
        if (json.status) {
            alert('Kredensial Cloudflare berhasil disimpan!');
            loadDashboardData();
            fetchCfZones();
        } else {
            alert('Gagal: ' + json.message);
        }
    } catch (e) {
        alert('Terjadi kesalahan koneksi');
    }
}

async function setCfSecurityLevel(level) {
    const zoneId = document.getElementById('cf_zone_selector').value;
    if (!zoneId) {
        alert('Pilih Domain / Zone terlebih dahulu di atas!');
        return;
    }

    if (level === 'under_attack' && !confirm('Aktifkan I AM UNDER ATTACK MODE di Cloudflare? Seluruh pengunjung akan melewati JS challenge.')) {
        return;
    }

    try {
        const res = await fetch('?api=cf_set_security_level', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({zone_id: zoneId, level: level})
        });
        const json = await res.json();
        if (json.success) {
            alert('Security level Cloudflare berhasil diubah ke: ' + level);
            loadCfZoneStatus(zoneId);
        } else {
            alert('Gagal: ' + (json.errors?.[0]?.message || 'Error'));
        }
    } catch (e) {
        alert('Gagal menghubungi API Cloudflare');
    }
}

async function blockIpCloudflare(e) {
    e.preventDefault();
    const zoneId = document.getElementById('cf_zone_selector').value;
    if (!zoneId) {
        alert('Pilih Domain / Zone terlebih dahulu di atas!');
        return;
    }

    const ip = document.getElementById('cf_block_ip_input').value;
    const mode = document.getElementById('cf_block_mode_input').value;
    const btn = document.getElementById('btnBlockCf');
    btn.disabled = true;

    try {
        const res = await fetch('?api=cf_block_ip', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({zone_id: zoneId, ip: ip, mode: mode, notes: 'Shielded from Panel'})
        });
        const json = await res.json();
        if (json.success) {
            alert(`IP ${ip} berhasil diterapkan (${mode}) di Cloudflare Edge!`);
            document.getElementById('cf_block_ip_input').value = '';
            loadCfZoneStatus(zoneId);
        } else {
            alert('Gagal: ' + (json.errors?.[0]?.message || 'Error'));
        }
    } catch (e) {
        alert('Error memblokir IP di Cloudflare');
    } finally {
        btn.disabled = false;
    }
}

async function quickBlockCf(ip) {
    const zoneId = document.getElementById('cf_zone_selector').value;
    if (!zoneId) {
        openTab('cloudflare');
        alert('Silakan pilih Zone ID Cloudflare terlebih dahulu di tab Cloudflare Shield!');
        return;
    }
    if (!confirm(`Blokir IP ${ip} di Cloudflare Edge?`)) return;

    try {
        const res = await fetch('?api=cf_block_ip', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({zone_id: zoneId, ip: ip, mode: 'block', notes: 'Pushed from Fail2ban'})
        });
        const json = await res.json();
        if (json.success) {
            alert(`IP ${ip} sekarang terblokir permanen di Cloudflare Edge!`);
        } else {
            alert('Gagal: ' + (json.errors?.[0]?.message || 'Error'));
        }
    } catch (e) {
        alert('Gagal');
    }
}

async function deleteCfRule(ruleId) {
    const zoneId = document.getElementById('cf_zone_selector').value;
    if (!confirm('Hapus aturan IP firewall ini dari Cloudflare?')) return;
    try {
        const res = await fetch('?api=cf_delete_rule', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({zone_id: zoneId, rule_id: ruleId})
        });
        const json = await res.json();
        if (json.success) {
            loadCfZoneStatus(zoneId);
        } else {
            alert('Gagal: ' + (json.errors?.[0]?.message || 'Error'));
        }
    } catch (e) {
        alert('Gagal');
    }
}

async function purgeCfCache() {
    const zoneId = document.getElementById('cf_zone_selector').value;
    if (!zoneId) {
        alert('Pilih Domain / Zone terlebih dahulu di atas!');
        return;
    }
    if (!confirm('Purge semua cache Cloudflare untuk domain ini?')) return;
    try {
        const res = await fetch('?api=cf_purge_cache', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({zone_id: zoneId})
        });
        const json = await res.json();
        if (json.success) {
            alert('Cache Cloudflare berhasil dibersihkan (Purged)!');
        } else {
            alert('Gagal: ' + (json.errors?.[0]?.message || 'Error'));
        }
    } catch (e) {
        alert('Error');
    }
}

// ZERO TRUST ACCESS LOGIC
async function fetchZtApps() {
    const zoneId = document.getElementById('cf_zone_selector')?.value || globalData.settings?.cf_default_zone_id;
    const tbody = document.getElementById('ztAppsTableBody');
    if (!tbody) return;

    if (!zoneId) {
        tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-slate-500">Pilih Zone ID di atas terlebih dahulu untuk melihat aplikasi Zero Trust.</td></tr>';
        return;
    }

    tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-slate-500">Memuat aplikasi Zero Trust dari Cloudflare...</td></tr>';
    try {
        const res = await fetch('?api=cf_get_access_apps&zone_id=' + encodeURIComponent(zoneId));
        const json = await res.json();
        if (json.success && json.result) {
            ztApps = json.result;
            if (ztApps.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-slate-500">Belum ada aplikasi Zero Trust di Zone ini. Klik tombol <b>Buat Zero Trust App Baru</b> di atas.</td></tr>';
            } else {
                tbody.innerHTML = ztApps.map(a => `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="p-3.5 font-bold text-white flex items-center space-x-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-purple-400"></span>
                            <span>${escapeHtml(a.name)}</span>
                        </td>
                        <td class="p-3.5 text-purple-300 font-mono text-xs font-semibold">${escapeHtml(a.domain)}</td>
                        <td class="p-3.5 text-slate-400 text-xs">${escapeHtml(a.session_duration || '24h')}</td>
                        <td class="p-3.5 text-slate-500 text-xs font-mono">${escapeHtml(a.id)}</td>
                        <td class="p-3.5 text-right">
                            <button onclick="deleteZtApp('${a.id}', '${escapeHtml(a.name)}')" class="text-red-400 hover:text-red-300 px-2.5 py-1 bg-slate-800 rounded text-xs"><i class="fa-solid fa-trash mr-1"></i>Hapus App</button>
                        </td>
                    </tr>
                `).join('');
            }
        } else {
            tbody.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-amber-400">Error: ${json.errors?.[0]?.message || 'Gagal mengambil data Zero Trust'}</td></tr>`;
        }
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-red-400">Gagal terhubung ke API Zero Trust.</td></tr>';
    }
}

function openCreateAccessModal() {
    document.getElementById('zt_form_name').value = '';
    document.getElementById('zt_form_domain').value = '';
    document.getElementById('zt_form_emails').value = '';
    document.getElementById('ztAppModal').classList.remove('hidden');
}

function closeCreateAccessModal() {
    document.getElementById('ztAppModal').classList.add('hidden');
}

async function saveZtApp(e) {
    e.preventDefault();
    const zoneId = document.getElementById('cf_zone_selector')?.value || globalData.settings?.cf_default_zone_id;
    if (!zoneId) {
        alert('Pilih Domain / Zone pada dropdown di atas terlebih dahulu!');
        return;
    }

    const btn = document.getElementById('saveZtAppBtn');
    btn.disabled = true;
    btn.innerText = 'Menerapkan ke Cloudflare...';

    const payload = {
        zone_id: zoneId,
        name: document.getElementById('zt_form_name').value,
        domain: document.getElementById('zt_form_domain').value,
        emails: document.getElementById('zt_form_emails').value,
        session_duration: document.getElementById('zt_form_duration').value
    };

    try {
        const res = await fetch('?api=cf_create_access_app', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const json = await res.json();
        if (json.success) {
            alert('Aplikasi Cloudflare Zero Trust berhasil dibuat dan diproteksi!');
            closeCreateAccessModal();
            fetchZtApps();
        } else {
            alert('Gagal: ' + (json.errors?.[0]?.message || 'Gagal membuat app'));
        }
    } catch (err) {
        alert('Terjadi kesalahan koneksi');
    } finally {
        btn.disabled = false;
        btn.innerText = 'Deploy Zero Trust App';
    }
}

async function deleteZtApp(appId, name) {
    const zoneId = document.getElementById('cf_zone_selector')?.value || globalData.settings?.cf_default_zone_id;
    if (!confirm(`Hapus proteksi Zero Trust untuk ${name}? Pengunjung tidak akan lagi melewati OTP.`)) return;
    try {
        const res = await fetch('?api=cf_delete_access_app', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({zone_id: zoneId, app_id: appId})
        });
        const json = await res.json();
        if (json.success) {
            fetchZtApps();
        } else {
            alert('Gagal: ' + (json.errors?.[0]?.message || 'Error'));
        }
    } catch (e) {
        alert('Gagal');
    }
}

// LOGS SYSTEM
async function fetchLogs() {
    const type = document.getElementById('logTypeSelect').value;
    const filter = document.getElementById('logFilterInput').value;
    try {
        const res = await fetch(`?api=get_logs&type=${type}&filter=${encodeURIComponent(filter)}&lines=100`);
        const json = await res.json();
        if (!json.status) return;

        currentLogs = json.logs;
        renderLogs();
    } catch (e) {
        console.error('Error fetching logs', e);
    }
}

function filterLogs() {
    fetchLogs();
}

function renderLogs() {
    const container = document.getElementById('logContainer');
    const summary = document.getElementById('logSummary');

    if (!currentLogs || currentLogs.length === 0) {
        container.innerHTML = '<div class="text-slate-500 italic p-4 text-center">Belum ada baris log untuk kategori ini.</div>';
        summary.innerText = 'Menampilkan 0 baris log.';
        return;
    }

    summary.innerText = `Menampilkan ${currentLogs.length} baris log terbaru.`;

    const html = currentLogs.map(line => {
        let colorClass = 'text-slate-300';
        let badge = '';

        if (line.includes('limiting requests') || line.includes('HTTP/1.1" 503') || line.includes('HTTP/1.1" 429')) {
            colorClass = 'text-amber-300 bg-amber-950/20 p-1 rounded border border-amber-900/50';
            badge = '<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 mr-1.5">[RATE-LIMIT DROP]</span>';
        } else if (line.includes('HTTP/1.1" 403')) {
            colorClass = 'text-red-300 bg-red-950/20 p-1 rounded border border-red-900/50';
            badge = '<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-400 mr-1.5">[BLOCKED 403]</span>';
        } else if (line.includes('HTTP/1.1" 200')) {
            colorClass = 'text-emerald-300/90';
        } else if (line.includes('[error]')) {
            colorClass = 'text-red-400 font-semibold';
        }

        return `<div class="${colorClass} hover:bg-slate-900/80 px-1 py-0.5 transition">${badge}${escapeHtml(line)}</div>`;
    }).join('');

    container.innerHTML = html;
}

async function clearLogs() {
    const type = document.getElementById('logTypeSelect').value;
    if (!confirm(`Yakin ingin membersihkan file log (${type})?`)) return;
    try {
        const res = await fetch(`?api=clear_logs&type=${type}`);
        const json = await res.json();
        alert(json.message);
        fetchLogs();
    } catch (e) {
        alert('Gagal membersihkan log');
    }
}

function toggleGeoIpInput() {
    const mode = document.getElementById('form_geoip_mode').value;
    const wrapper = document.getElementById('geoipCountriesWrapper');
    if (mode === 'off') {
        wrapper.classList.add('hidden');
    } else {
        wrapper.classList.remove('hidden');
    }
}

function setGeoPreset(countries) {
    document.getElementById('form_geoip_countries').value = countries;
    if (countries === 'CN,RU,US') {
        document.getElementById('form_geoip_mode').value = 'block_only';
    } else {
        document.getElementById('form_geoip_mode').value = 'allow_only';
    }
    toggleGeoIpInput();
}

function openDomainModal() {
    document.getElementById('modalTitle').innerText = 'Tambah Konfigurasi Domain';
    document.getElementById('form_domain_id').value = '0';
    document.getElementById('form_domain_name').value = '';
    document.getElementById('form_is_wildcard').checked = false;
    document.getElementById('form_require_zt_access').checked = false;
    document.getElementById('form_geoip_mode').value = 'off';
    document.getElementById('form_geoip_countries').value = '';
    document.getElementById('form_target_type').value = 'local_php';
    document.getElementById('form_target_value').value = '/var/www/html';
    document.getElementById('form_custom_rate').value = '';
    document.getElementById('form_custom_burst').value = '';
    toggleTargetInput();
    toggleGeoIpInput();
    document.getElementById('domainModal').classList.remove('hidden');
}

function editDomain(id) {
    const d = globalData.domains.find(x => x.id == id);
    if (!d) return;

    document.getElementById('modalTitle').innerText = 'Edit Domain: ' + d.domain;
    document.getElementById('form_domain_id').value = d.id;
    document.getElementById('form_domain_name').value = d.domain;
    document.getElementById('form_is_wildcard').checked = d.is_wildcard == 1;
    document.getElementById('form_require_zt_access').checked = d.require_zt_access == 1;
    document.getElementById('form_geoip_mode').value = d.geoip_mode || 'off';
    document.getElementById('form_geoip_countries').value = d.geoip_countries || '';
    document.getElementById('form_target_type').value = d.target_type;
    document.getElementById('form_target_value').value = d.target_value;
    document.getElementById('form_custom_rate').value = d.custom_rate_limit > 0 ? d.custom_rate_limit : '';
    document.getElementById('form_custom_burst').value = d.custom_rate_burst > 0 ? d.custom_rate_burst : '';
    toggleTargetInput();
    toggleGeoIpInput();
    document.getElementById('domainModal').classList.remove('hidden');
}

function closeDomainModal() {
    document.getElementById('domainModal').classList.add('hidden');
}

async function saveDomain(e) {
    e.preventDefault();
    const btn = document.getElementById('saveDomainBtn');
    btn.disabled = true;
    btn.innerText = 'Menyimpan & Reload...';

    const payload = {
        id: document.getElementById('form_domain_id').value,
        domain: document.getElementById('form_domain_name').value,
        is_wildcard: document.getElementById('form_is_wildcard').checked ? 1 : 0,
        require_zt_access: document.getElementById('form_require_zt_access').checked ? 1 : 0,
        geoip_mode: document.getElementById('form_geoip_mode').value,
        geoip_countries: document.getElementById('form_geoip_countries').value,
        target_type: document.getElementById('form_target_type').value,
        target_value: document.getElementById('form_target_value').value,
        custom_rate_limit: document.getElementById('form_custom_rate').value || 0,
        custom_rate_burst: document.getElementById('form_custom_burst').value || 0
    };

    try {
        const res = await fetch('?api=save_domain', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const json = await res.json();
        if (json.status) {
            closeDomainModal();
            loadDashboardData();
        } else {
            alert('Gagal: ' + json.message);
        }
    } catch (err) {
        alert('Terjadi kesalahan network');
    } finally {
        btn.disabled = false;
        btn.innerText = 'Simpan Domain';
    }
}

async function deleteDomain(id, name) {
    if (!confirm(`Hapus domain ${name}?`)) return;
    try {
        const res = await fetch('?api=delete_domain', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({id})
        });
        const json = await res.json();
        if (json.status) {
            loadDashboardData();
        } else {
            alert('Gagal menghapus: ' + json.message);
        }
    } catch (err) {
        alert('Error');
    }
}

async function saveSettings(e) {
    e.preventDefault();
    const payload = {
        global_client_rate: document.getElementById('setting_global_client_rate').value,
        global_client_burst: document.getElementById('setting_global_client_burst').value,
        global_conn_limit: document.getElementById('setting_global_conn_limit').value,
        fail2ban_bantime: document.getElementById('setting_fail2ban_bantime').value || '10m',
        fail2ban_findtime: document.getElementById('setting_fail2ban_findtime').value || '1m',
        fail2ban_maxretry: document.getElementById('setting_fail2ban_maxretry').value || '5',
        block_bad_bots: document.getElementById('setting_block_bad_bots').checked ? '1' : '0',
        block_hidden_files: document.getElementById('setting_block_hidden_files').checked ? '1' : '0',
        cf_auto_sync_ban: document.getElementById('setting_cf_auto_sync_ban').checked ? '1' : '0',
        cf_auto_ban_mode: document.getElementById('setting_cf_auto_ban_mode').value,
        new_password: document.getElementById('setting_new_password').value
    };

    try {
        const res = await fetch('?api=save_settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        const json = await res.json();
        if (json.status) {
            alert('Pengaturan berhasil disimpan dan Nginx + Fail2ban berhasil direload!');
            document.getElementById('setting_new_password').value = '';
            loadDashboardData();
        } else {
            alert('Gagal: ' + json.message);
        }
    } catch (err) {
        alert('Error');
    }
}

async function unbanIp(ip, jail) {
    if (!confirm(`Unban IP ${ip}?`)) return;
    try {
        const res = await fetch('?api=unban_ip', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip, jail})
        });
        const json = await res.json();
        alert('Hasil: ' + json.message);
        loadDashboardData();
    } catch (e) {
        alert('Error');
    }
}

async function logout() {
    await fetch('?api=logout');
    window.location.reload();
}

function escapeHtml(text) {
    if (!text) return '';
    return text.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// Initial boot
openTab('domains');
loadDashboardData();
setInterval(() => {
    if (activeTab === 'logs') {
        fetchLogs();
    } else {
        loadDashboardData();
    }
}, 5000);
</script>

<?php endif; ?>
</body>
</html>
