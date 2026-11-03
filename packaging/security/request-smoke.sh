#!/bin/sh
# Isolated container only: local fake LAPI validates bouncer behavior, not a real engine.
set -eu
work=$(mktemp -d)
nginx_pid=
cleanup() { [ -z "$nginx_pid" ] || kill "$nginx_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
chmod 755 "$work"
printf 'ok\n' > "$work/index.html"
cp /usr/local/share/nginx-ui-security/initial-policy.conf "$work/policy.conf"
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$work/policy.conf"
cat > "$work/bouncer.conf" <<'BOUNCER'
ENABLED=true
API_URL=http://127.0.0.1:18081
API_KEY=smoke-only-not-a-secret
MODE=live
CACHE_EXPIRATION=1
BOUNCING_ON_TYPE=all
FALLBACK_REMEDIATION=ban
RET_CODE=403
BAN_TEMPLATE_PATH=/var/lib/crowdsec/lua/templates/ban.html
BOUNCER
cat > "$work/nginx.conf" <<CONFIG
include /etc/nginx/modules-enabled/*.conf;
pid $work/nginx.pid;
error_log stderr;
events {}
http {
 lua_package_path '/usr/local/lua/crowdsec/?.lua;;';
 lua_shared_dict crowdsec_cache 5m;
 init_by_lua_block { local cs = require('crowdsec'); local ok,err=cs.init('$work/bouncer.conf', 'smoke/1'); if ok == nil then error(err) end }
 server { listen 127.0.0.1:18081;
   location /v1/decisions { content_by_lua_block {
     local file=io.open('$work/ban', 'r');
     if file then file:close(); ngx.say('[{"type":"ban","origin":"cscli","value":"127.0.0.1","scope":"Ip"}]') else ngx.print('null') end
   } }
 }
 server { listen 127.0.0.1:18080; root $work;
   modsecurity on; modsecurity_rules_file $work/policy.conf;
   location / { access_by_lua_block { require('crowdsec').Allow(ngx.var.remote_addr) } content_by_lua_block { ngx.say('ok') } }
 }
}
CONFIG
nginx -t -c "$work/nginx.conf"
nginx -c "$work/nginx.conf" -g 'daemon off;' &
nginx_pid=$!
for attempt in 1 2 3 4 5; do
 if curl -fsS http://127.0.0.1:18080/ >/dev/null 2>&1; then break; fi
 sleep 1
done
code() { curl -s -o /dev/null -w '%{http_code}' "$1"; }
test "$(code http://127.0.0.1:18080/)" = 200
test "$(code 'http://127.0.0.1:18080/?q=%3Cscript%3Ealert(1)%3C/script%3E')" = 403
post_code() { curl -s -o /dev/null -w '%{http_code}' -H "Content-Type: $1" --data-binary "$2" http://127.0.0.1:18080/; }
test "$(post_code application/json '{"name":"ordinary value"}')" = 200
test "$(post_code application/xml '<root><name>ordinary value</name></root>')" = 200
test "$(post_code application/json '{"q":"\u003cscript\u003ealert(1)\u003c/script\u003e"}')" = 403
test "$(post_code application/problem+json '{"q":"\u003cscript\u003ealert(1)\u003c/script\u003e"}')" = 403
test "$(post_code application/json '{"q":')" = 400
test "$(post_code application/xml '<root><name>broken</root>')" = 400
printf '%s\n' 'PASS: JSON/XML normal 200, escaped JSON/+json attack 403, malformed JSON/XML 400'
touch "$work/ban"
sleep 2
test "$(code http://127.0.0.1:18080/)" = 403
rm "$work/ban"
sleep 2
test "$(code http://127.0.0.1:18080/)" = 200
printf '%s\n' 'PASS: normal 200, CRS attack 403, mocked CrowdSec ban 403, removed ban 200'
