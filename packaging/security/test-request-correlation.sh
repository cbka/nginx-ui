#!/bin/sh
# Network-isolated real Nginx/ModSecurity test; no production state mounted.
set -eu
cd "$(dirname "$0")/../.."
image=${1:-codex/nginx-ui-security:prod-sync-security11-r2}
timeout 40 docker run -i --rm --network none --memory 192m --memory-swap 192m --cpus 1 --pids-limit 64 \
 --label codex.task=nginx-ui-request-correlation-test --entrypoint sh \
 -v "$PWD/packaging/security:/test:ro" "$image" -es <<'CONTAINER'
mkdir -p /usr/local/lua/nginx-ui
cp /test/request-reference-header.lua /test/request-reference-body.lua /usr/local/lua/nginx-ui/
cat >/tmp/modsec.conf <<"RULES"
SecRuleEngine On
SecAuditEngine RelevantOnly
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog /tmp/modsec-audit.json
SecAuditLogParts ABIJDEFHZ
SecRule REQUEST_URI "@streq /modsec" "id:100001,phase:1,deny,status:403,log,msg:correlation-test"
RULES
cat >/tmp/test-nginx.conf <<"CONF"
include /etc/nginx/modules-enabled/*.conf;
pid /tmp/request-correlation.pid;
error_log /tmp/request-correlation-error.log;
events {}
http {
 lua_package_path "/test/?.lua;;";
 include /test/request-correlation.conf;
 gzip on;
 gzip_min_length 1;
 gzip_proxied any;
 access_log /var/log/nginx/request-correlation.log nginx_ui_request_json;
 server { listen 127.0.0.1:8082;
  location /json { default_type application/json; add_header WWW-Authenticate 'Basic realm="test"' always; return 401 '{"error":"authenticate"}'; }
  location /html { default_type text/html; add_header WWW-Authenticate 'Basic realm="test"' always; return 401 '<html><body>Maintenance / login context preserved</body></html>'; }
  location /encoded { content_by_lua_block { ngx.status=503; ngx.header.content_type="text/html"; ngx.header.content_encoding="gzip"; ngx.print(ngx.decode_base64("H4sIAAAAAAAC/7PJKMnNsbNJyk+ptEvNS85PSU1RSM7PK0nNK7HRB4va6IOVAAAcLNQtKQAAAA==")) } }
  location / { add_header X-Request-ID upstream-forged always; return 200 "upstream"; }
 }
 server { listen 127.0.0.1:8089;
  modsecurity on; modsecurity_rules_file /tmp/modsec.conf;
  location /ok { add_header X-Other preserved always; return 200 "ok"; }
  location /encoded { proxy_pass http://127.0.0.1:8082; }
  location /html { proxy_pass http://127.0.0.1:8082; }
  location /json { proxy_pass http://127.0.0.1:8082; }
  location /upstream { proxy_pass http://127.0.0.1:8082; }
  location /stream { default_type text/html; content_by_lua_block { ngx.status=503; ngx.print("<html><bo"); ngx.flush(true); ngx.print("dy>streamed maintenance</body></html>") } }
  location /large { default_type text/html; content_by_lua_block { ngx.status=503; ngx.print("<html><body>" .. string.rep("x",70000) .. "</body></html>") } }
  location /status/ { content_by_lua_block { ngx.exit(tonumber(ngx.var.uri:match("(%d+)$"))) } }
  location /modsec { content_by_lua_block { ngx.say("should be denied") } }
  location /redirect { error_page 418 =403 /_error; return 418; }
  location = /_error { internal; default_type text/html; return 403 "$request_id"; }
 }
}
CONF
nginx -t -c /tmp/test-nginx.conf
nginx -c /tmp/test-nginx.conf
trap "nginx -c /tmp/test-nginx.conf -s quit" EXIT
python3 /test/test_request_correlation_runtime.py
CONTAINER
