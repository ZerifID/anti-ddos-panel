#!/bin/bash
ACTION="$1"
IP="$2"
CONF="/etc/nginx/conf.d/fail2ban-denylist.conf"

[ -f "$CONF" ] || touch "$CONF"

if [ "$ACTION" = "ban" ]; then
    if [ -n "$IP" ] && ! grep -Fq "deny $IP;" "$CONF" 2>/dev/null; then
        echo "deny $IP;" >> "$CONF"
        /usr/sbin/nginx -t 2>/dev/null && /usr/sbin/nginx -s reload 2>/dev/null
    fi
    # Auto deploy to Cloudflare Edge WAF in background
    if [ -f "/opt/ddos-panel/cf-sync-ban.php" ]; then
        /usr/bin/php /opt/ddos-panel/cf-sync-ban.php ban "$IP" >/dev/null 2>&1 &
    fi
elif [ "$ACTION" = "unban" ]; then
    if [ -n "$IP" ]; then
        sed -i "/deny $(echo "$IP" | sed 's/[^^]/[&]/g');/d" "$CONF" 2>/dev/null
        /usr/sbin/nginx -t 2>/dev/null && /usr/sbin/nginx -s reload 2>/dev/null
    fi
    # Auto remove from Cloudflare Edge WAF in background
    if [ -f "/opt/ddos-panel/cf-sync-ban.php" ]; then
        /usr/bin/php /opt/ddos-panel/cf-sync-ban.php unban "$IP" >/dev/null 2>&1 &
    fi
fi
