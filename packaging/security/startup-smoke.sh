#!/bin/sh
# Disposable, network-isolated container only. Never run against mounted real state.
set -eu
pid=
cleanup() { [ -z "$pid" ] || kill "$pid" 2>/dev/null || true; [ -z "$pid" ] || wait "$pid" 2>/dev/null || true; }
trap cleanup EXIT HUP INT TERM
test ! -e /usr/local/etc/nginx-ui/app.ini
cat > /usr/local/etc/nginx-ui/app.ini <<'CONFIG'
[server]
Host = 127.0.0.1
Port = 9000
RunMode = release
[database]
Name = smoke
[security_center]
Enabled = true
CONFIG
/usr/local/sbin/entrypoint.sh >/tmp/startup-smoke.log 2>&1 &
pid=$!
ready=false
for attempt in $(seq 1 30); do
 if curl -fsS http://127.0.0.1:9000/ >/tmp/startup-home.html 2>/dev/null; then ready=true; break; fi
 kill -0 "$pid"
 sleep 1
done
test "$ready" = true
grep -q '<html' /tmp/startup-home.html
status=$(curl -s -o /tmp/startup-security-response.json -w '%{http_code}' http://127.0.0.1:9000/api/security-center/status)
test "$status" = 401 -o "$status" = 403
template_status=$(curl -s -o /tmp/startup-template-response.json -w '%{http_code}' http://127.0.0.1:9000/api/security-center/templates)
test "$template_status" = 401 -o "$template_status" = 403
sharing_status=$(curl -s -o /tmp/startup-sharing-response.json -w '%{http_code}' http://127.0.0.1:9000/api/security-center/crowdsec/sharing)
test "$sharing_status" = 401 -o "$sharing_status" = 403
if [ -n "${EXPECTED_SECURITY_ASSET:-}" ]; then
 curl -fsS "http://127.0.0.1:9000/assets/$EXPECTED_SECURITY_ASSET" > /tmp/startup-security-asset.js
 printf '%s  /tmp/startup-security-asset.js\n' "$EXPECTED_SECURITY_ASSET_SHA256" | sha256sum -c -
 grep -q 'Unsaved template draft' /tmp/startup-security-asset.js
 grep -q 'Community signal sharing' /tmp/startup-security-asset.js
fi
sleep 2
/usr/bin/supervisorctl -c /etc/supervisor/security-runtime.conf status nginx | grep -q RUNNING
/usr/bin/supervisorctl -c /etc/supervisor/security-runtime.conf status nginx-ui | grep -q RUNNING
printf 'PASS: actual fork binary serves embedded UI under supervisor; unauthenticated security/template/sharing APIs protected; security API returns %s\n' "$status"
