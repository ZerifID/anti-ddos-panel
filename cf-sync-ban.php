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

    if (!$autoSync || empty($apiKey) || empty($apiEmail)) {
        exit(0);
    }

    // If default zone id is empty in settings, auto-detect active zone from Cloudflare account
    if (empty($zoneId)) {
        $zones = CloudflareAPI::getZones($apiKey, $apiEmail);
        if (!empty($zones['result'][0]['id'])) {
            $zoneId = $zones['result'][0]['id'];
        }
    }

    if (empty($zoneId)) {
        exit(0);
    }

    if ($action === 'ban') {
        CloudflareAPI::blockIpOnCloudflare(
            $zoneId,
            $ip,
            $mode,
            'Auto-banned by Fail2ban Anti-DDoS Panel',
            $apiKey,
            $apiEmail
        );
    } elseif ($action === 'unban') {
        CloudflareAPI::deleteIpAccessRuleByIp($zoneId, $ip, $apiKey, $apiEmail);
    }
} catch (Exception $e) {
    // Silent fail in background
}
