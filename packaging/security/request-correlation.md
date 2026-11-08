# Request references

Include `request-correlation.conf` inside `http {}` after loading the Lua and
ModSecurity modules. Add `/usr/local/lua/nginx-ui/?.lua` to `lua_package_path`.
The image packages this include under `/usr/local/share/nginx-ui-security/` and
the Lua helpers under `/usr/local/lua/nginx-ui/`. Installation does not silently
rewrite persisted Nginx configuration.

Nginx generates `$request_id` (32 hexadecimal characters). It is returned in
`X-Request-ID`, used as `modsecurity_transaction_id`, and is already recorded as
`transaction_id` by local AppSec and CrowdSec remediation events. Client and
upstream response headers cannot select the returned reference. The AppSec
inspection request also receives the server-owned `X-Request-ID`.

Extend existing access formats with `$request_id` so the existing collector can
index/search the field. An optional JSON format is included for environments
without an existing log integration. Do not enable duplicate access logs by
default, and do not promote individual IDs to Loki labels. Explicit child
`access_log` settings override inherited logs. A child Lua header/body filter
must call the same helper functions, since Nginx does not merge Lua filters.

HTML error responses with status 401, 403 or 500–599 receive a visible reference
before their closing body tag. Plain text served as HTML can also be annotated.
The original maintenance/error content and authentication headers are retained.
If an upstream Nginx UI already inserted the exact managed reference block, it
is replaced with the current edge reference so clients see one authoritative ID.
Only the canonical native Nginx footer is removed, and only with no upstream.
The filter buffers at most 64 KiB; oversized, malformed/open-tag fragments,
already encoded upstream bodies, and JSON/other non-HTML responses are preserved
without a visible body reference. The response header still carries the ID.
Normal Nginx gzip compression after the filter is supported. Modified HTML error
responses remove stale body validators/length and carry `Cache-Control: no-store`.
HEAD responses remain bodyless. IDs refer to requests, not to global CrowdSec IP
decisions, which can aggregate many requests.

Run `packaging/security/test-request-correlation.sh IMAGE` for a real isolated
Nginx + ModSecurity smoke test and `packaging/security/test-appsec.sh IMAGE` for
AppSec transport regression. The tests use disposable containers with hard
memory/CPU/PID limits, no external network, and no production state mounts.
