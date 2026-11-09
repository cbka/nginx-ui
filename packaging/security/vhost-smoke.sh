#!/bin/sh
# Network-isolated: CrowdSec decisions come from a local mock, not a real engine.
set -eu
work=$(mktemp -d)
nginx_pid=
cleanup() { [ -z "$nginx_pid" ] || kill "$nginx_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
chmod 755 "$work"
site_a=$(printf default.test | sha256sum | cut -d ' ' -f 1)
site_b=$(printf override.test | sha256sum | cut -d ' ' -f 1)
mkdir "$work/policies"
printf '{"name":"default.test"}\n' > "$work/policies/$site_a.json"
printf '{"name":"override.test"}\n' > "$work/policies/$site_b.json"
cp /usr/local/share/nginx-ui-security/initial-policy.conf "$work/global.conf"
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$work/global.conf"
printf '%s\n' 'SecRule ARGS:policytest "@streq scoped" "id:999998,phase:2,t:none,deny,status:403,log,msg:scoped-test"' >> "$work/global.conf"
printf '%s\n' 'SecRule ARGS:query "@streq scoped" "id:999997,phase:2,t:none,deny,status:403,log,msg:target-test"' >> "$work/global.conf"
printf 'SecAuditLog %s/%s.json\n' "$work" "$site_a" >> "$work/global.conf"
cp "$work/global.conf" "$work/override.conf"
printf '%s\n' 'SecRule REQUEST_FILENAME "@streq /search" "id:2000000,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=999997;ARGS:query"' >> "$work/override.conf"
printf '%s\n' 'SecRule REQUEST_FILENAME "@streq /private" "id:2100000,phase:1,deny,status:403,log,t:none,msg:site-path-block"' >> "$work/override.conf"
printf 'SecAuditLog %s/%s.json\n' "$work" "$site_b" >> "$work/override.conf"
printf '%s\n' 'SecRuleRemoveById 999998' >> "$work/override.conf"
mkdir -p /etc/crowdsec/bouncers
cat > /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf <<'BOUNCER'
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
error_log $work/error.log notice;
events {}
http {
 include /usr/local/share/nginx-ui-security/crowdsec-init.conf;
 include /usr/local/share/nginx-ui-security/request-correlation.conf;
 access_log $work/access.jsonl nginx_ui_request_json;
 server { listen 127.0.0.1:18081;
  location /v1/decisions { content_by_lua_block {
   local file=io.open('$work/ban','r');
   if file then file:close(); ngx.say('[{"type":"ban","origin":"cscli","value":"127.0.0.1","scope":"Ip"}]') else ngx.print('null') end
  } }
 }
 server { listen 127.0.0.1:18082; server_name legacy.test;
  set \$nginx_ui_crowdsec_enabled 1;
  access_by_lua_file /usr/local/lua/nginx-ui/security-access.lua;
  location / { content_by_lua_block { ngx.say('legacy no site id') } }
 }
 server { listen 127.0.0.1:18080; server_name default.test;
  modsecurity on; modsecurity_rules_file $work/global.conf;
  set \$nginx_ui_security_site_id $site_a;
  set \$nginx_ui_crowdsec_enabled 1;
  access_by_lua_file /usr/local/lua/nginx-ui/security-access.lua;
  location / { content_by_lua_block { ngx.say('default host') } }
  location = /application-denied { content_by_lua_block { ngx.exit(403) } }
 }
 server { listen 127.0.0.1:18080; server_name override.test;
  modsecurity on; modsecurity_rules_file $work/override.conf;
  set \$nginx_ui_security_site_id $site_b;
  set \$nginx_ui_crowdsec_enabled 0;
  access_by_lua_file /usr/local/lua/nginx-ui/security-access.lua;
  location / { content_by_lua_block { ngx.say('override host') } }
 }
}
CONFIG
nginx -t -c "$work/nginx.conf"
nginx -c "$work/nginx.conf" -g 'daemon off;' &
nginx_pid=$!
code() { curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1:18080/$2"; }
for attempt in 1 2 3 4 5; do
 if curl -fsS -H 'Host: default.test' http://127.0.0.1:18080/ >/dev/null 2>&1; then break; fi
 sleep 1
done
test "$(code default.test '')" = 200
test "$(code default.test 'application-denied')" = 403
test "$(code override.test '')" = 200
test "$(code default.test '?policytest=scoped')" = 403
test "$(code override.test '?policytest=scoped')" = 200
test "$(code default.test 'search?query=scoped')" = 403
test "$(code override.test 'search?query=scoped')" = 200
test "$(code override.test 'other?query=scoped')" = 403
test "$(code override.test 'private?token=harmless')" = 403
test "$(code override.test 'private-more')" = 200
test "$(code default.test 'private?token=harmless')" = 200
printf '%s\n' 'PASS: scoped target exception only on intended host/path; exact path block includes query but not prefix'
attack='?q=%3Cscript%3Ealert(1)%3C/script%3E'
test "$(code default.test "$attack")" = 403
test "$(code override.test "$attack")" = 403
# Only the shared/default policy follows a global change; override remains blocking.
sed -i 's/SecRuleEngine On/SecRuleEngine DetectionOnly/' "$work/global.conf"
nginx -t -c "$work/nginx.conf"
nginx -s reload -c "$work/nginx.conf"
sleep 1
test "$(code default.test "$attack")" = 200
test "$(code override.test "$attack")" = 403
# Same source IP and same central decision: enforcement is a per-server choice.
touch "$work/ban"
sleep 2
test "$(curl -s -D "$work/ban-headers" -o "$work/ban-body" -w '%{http_code}' -H 'Host: default.test' -H 'X-Request-ID: forged-client-reference' http://127.0.0.1:18080/)" = 403
test "$(code override.test '')" = 200
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18082/)" = 403
rm "$work/ban"
sleep 2
test "$(code default.test '')" = 200
printf '%s\n' 'PASS: per-host exclusion isolated; global default change isolated from explicit override; CrowdSec ban enforced on A and bypassed on B'
# Demonstrate why parent rulesfile + complete child rulesfile is rejected.
sed '/^http {/a\ modsecurity_rules_file REPLACE_PARENT;' "$work/nginx.conf" | sed "s|REPLACE_PARENT|$work/global.conf|" > "$work/duplicate.conf"
if nginx -t -c "$work/duplicate.conf" > "$work/duplicate.log" 2>&1; then
 echo 'Unexpectedly accepted duplicate parent and child complete rulesets' >&2
 exit 1
fi
printf '%s\n' 'PASS: duplicate parent/child full rulesets fail validation; configure exactly one full ruleset per server'

python3 - "$work" <<'AUDIT'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for audit in root.glob("*.json"):
    name = audit.name
    records = [json.loads(line)['transaction'] for line in audit.read_text().splitlines()]
    assert records, name
    assert all('headers' not in t['request'] and 'body' not in t['request'] for t in records)
    assert all('headers' not in t['response'] and 'body' not in t['response'] for t in records)
print('PASS: separate per-vhost audit files contain no request/response headers or bodies')
AUDIT

python3 - "$work" <<'EVENTS'
import json, pathlib, sys
sys.path.insert(0, '/usr/local/lib/nginx-ui-security')
from audit_reader import Reader
root = pathlib.Path(sys.argv[1])
reader = Reader(root, root/'policies', root/'events.jsonl', root/'cursors', 'smoke-node', root/'error.log')
reader.scan()
events = [json.loads(line) for line in (root/'events.jsonl').read_text().splitlines()]
crowd = [event for event in events if event['source']=='crowdsec']
assert len(crowd)==2, crowd
assert sorted(event['vhost'] for event in crowd)==['', 'default.test'], crowd
crowd = [event for event in crowd if event['vhost']=='default.test']
assert crowd[0]['action']=='ban' and crowd[0]['node']=='smoke-node', crowd
assert crowd[0]['transaction_id'] and crowd[0]['event_time'].endswith('Z'), crowd
headers = [line.split(':', 1)[1].strip() for line in (root/'ban-headers').read_text().splitlines() if line.lower().startswith('x-request-id:')]
assert headers == [crowd[0]['transaction_id']], (headers, crowd)
assert 'Referenz-ID: <code>' + headers[0] + '</code>' in (root/'ban-body').read_text()
assert '<!-- nginx-ui-request-reference -->' not in (root/'ban-body').read_text()
assert (root/'ban-body').read_text().index('Referenz-ID: <code>') < (root/'ban-body').read_text().index('</main>')
assert 'forged-client-reference' not in headers
access = [json.loads(line) for line in (root/'access.jsonl').read_text().splitlines()]
assert any(row['request_id']==headers[0] and row['status']==403 and row['host']=='default.test' for row in access)
print('PASS: real CrowdSec bouncer403 has same server ID in response header, HTML reference, access log and normalized security event')
assert all(event['event_time'].endswith('Z') for event in events), events
assert all('?' not in event['path'] for event in events), events
reader = Reader(root, root/'policies', root/'events.jsonl', root/'cursors', 'smoke-node', root/'error.log')
reader.scan()
assert len((root/'events.jsonl').read_text().splitlines()) == len(events)
print('PASS: actual CrowdSec enforcement event attributed only to A; B bypass and application403 generate none; legacy missing identity still blocked/unattributed; original timestamps and restart cursor verified')
EVENTS
