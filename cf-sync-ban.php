<?php
// Background trigger executed by Fail2ban action
if ($argc < 3) {
    exit(0);
}

$action = $argv[1]; // 'ban' or 'unban'
$ip = trim($argv[2]);

if (empty($ip)) {
    exit(0);
}

require_once __DIR__ . '/engine.php';

try {
    $settings = PanelEngine::getSettings();
    $autoSync = ($settings['cf_auto_sync_ban'] ?? '0') === '1';
    $apiKey = $settings['cf_api_key'] ?? '';
    $apiEmail = $settings['cf_api_email'] ?? '';
    $zoneId = $settings['cf_default_zone_id'] ?? '';
    $mode = $settings['cf_auto_ban_mode'] ?? 'block';

    if (!$autoSync || empty($apiKey) || empty($apiEmail) || empty($zoneId)) {
        exit(0);
    }

    if ($action === 'ban') {
        CloudflareAPI::addIpAccessRule(
            $zoneId,
            $apiKey,
            $apiEmail,
            $ip,
            $mode,
            'Auto-banned by Fail2ban Anti-DDoS Panel'
        );
    } elseif ($action === 'unban') {
        $rules = CloudflareAPI::getIpAccessRules($zoneId, $apiKey, $apiEmail);
        if (is_array($rules)) {
            foreach ($rules as $r) {
                if (isset($r['configuration']['value']) && $r['configuration']['value'] === $ip) {
                    CloudflareAPI::deleteIpAccessRule($zoneId, $apiKey, $apiEmail, $r['id']);
                }
            }
        }
    }
} catch (Exception $e) {
    // Silent fail in background
}
