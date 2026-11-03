#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
image=${1:-codex/nginx-ui-security:prod-3.0.0-security.4}
timeout 30 docker run --rm --network none --memory 128m --memory-swap 128m --cpus 1 --pids-limit 64 --label codex.task=nginx-ui-ip-allowlist-test --entrypoint sh -v "$PWD/packaging/security:/test:ro" "$image" -ec '
cat >/tmp/test-nginx.conf <<"CONF"
include /etc/nginx/modules-enabled/*.conf;
pid /tmp/test-nginx.pid;
error_log stderr;
events {}
http {
 access_log off;
 lua_package_path "/test/?.lua;/usr/local/lua/crowdsec/?.lua;;";
 server { listen 127.0.0.1:8089; location / { content_by_lua_file /test/ip-allowlist-test.lua; } }
}
CONF
nginx -c /tmp/test-nginx.conf
trap "nginx -c /tmp/test-nginx.conf -s quit" EXIT
curl --fail --silent --show-error http://127.0.0.1:8089/
'
