#!/bin/sh
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cat > "$work/modsecurity.conf" <<'RULES'
SecRuleEngine DetectionOnly
Include /etc/modsecurity/modsecurity.conf
Include /etc/modsecurity/crs/crs-setup.conf
Include /usr/share/modsecurity-crs/rules/*.conf
RULES
cat > "$work/nginx.conf" <<CONFIG
include /etc/nginx/modules-enabled/*.conf;
pid $work/nginx.pid;
error_log stderr;
events {}
http {
    lua_package_path '/usr/local/lua/crowdsec/?.lua;;';
    init_by_lua_block { require('crowdsec'); require('resty.http'); require('cjson') }
    modsecurity on;
    modsecurity_rules_file $work/modsecurity.conf;
    server { listen 127.0.0.1:18080; location / { access_by_lua_block { } } }
}
CONFIG
/usr/sbin/nginx -t -c "$work/nginx.conf"
/usr/bin/cscli version
