#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
image=${1:-codex/nginx-ui-security:prod-3.0.0-security.4}
timeout 30 docker run --rm --network none --memory 128m --memory-swap 128m --cpus 1 --pids-limit 64 --label codex.task=nginx-ui-appsec-test --entrypoint sh -v "$PWD/packaging/security:/test:ro" "$image" -ec '
mkdir -p /etc/crowdsec/bouncers
printf "%s" "test-only-key" >/etc/crowdsec/bouncers/nginx-ui-appsec.key
printf "%s" "file-backed-body" >/tmp/spooled-body
cat >/etc/crowdsec/bouncers/nginx-ui-appsec.json <<"JSON"
{"block_url":"http://127.0.0.1:7422", "detection_url":"http://127.0.0.1:7423", "key_file":"/etc/crowdsec/bouncers/nginx-ui-appsec.key"}
JSON
cat >/tmp/test-nginx.conf <<"CONF"
include /etc/nginx/modules-enabled/*.conf;
pid /tmp/test-nginx.pid;
error_log /tmp/security-events.log;
events {}
http {
 include /test/request-correlation.conf;
 access_log /tmp/access.jsonl nginx_ui_request_json;
 lua_package_path "/test/?.lua;/usr/local/lua/crowdsec/?.lua;;";
 server { set $nginx_ui_security_site_id ""; listen 127.0.0.1:8089; location / { content_by_lua_file /test/appsec-logging-test.lua; } }
}
CONF
nginx -c /tmp/test-nginx.conf
trap "nginx -c /tmp/test-nginx.conf -s quit" EXIT
curl --fail --silent --show-error -D /tmp/detected-headers http://127.0.0.1:8089/
test "$(curl --silent --show-error -D /tmp/blocked-headers -o /tmp/blocked-body -w "%{http_code}" -H "X-Request-ID: forged-client-reference" http://127.0.0.1:8089/blocked)" = 403
PYTHONPATH=/test python3 - <<"PY"
import json
from pathlib import Path
from audit_normalizer import structured_crowdsec
rows=[]
for line in open("/tmp/security-events.log"):
    rows.extend(structured_crowdsec(line,"test-node","/tmp"))
assert {r["action"] for r in rows} == {"detected","ban","blocked"}, rows
blocked = next(r for r in rows if r["action"] == "blocked")
ids = [line.split(":",1)[1].strip() for line in Path("/tmp/blocked-headers").read_text().splitlines() if line.lower().startswith("x-request-id:")]
assert ids == [blocked["transaction_id"]], (ids, blocked)
assert ids[0] in Path("/tmp/blocked-body").read_text()
assert "Referenz-ID:" in Path("/tmp/blocked-body").read_text()
assert ids[0] != "forged-client-reference"
access = [json.loads(line) for line in Path("/tmp/access.jsonl").read_text().splitlines()]
assert any(r["request_id"] == ids[0] and r["status"] == 403 for r in access)
print("PASS: AppSec blocking with mocked inspection transport matches response header/body, access log and normalized event ID")
print("PASS AppSec and IP-remediation events survive default Nginx error severity and normalize")
PY
'
