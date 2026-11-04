# Per-site CrowdSec AppSec runtime

The existing IP decision bouncer and AppSec are independent. Generated Nginx
policies select `nginx_ui_appsec_mode` (`off`, `detection`, `block`), and set
`crowdsec_disable_appsec 1` to prevent the upstream IP bouncer from invoking
AppSec a second time. A CrowdSec IP/CIDR allowlist skips both checks. Removing
the plugin's request hook disables both.

Install `nginx_ui_appsec.lua` beside `security-access.lua`. During the existing
**master** `init_by_lua_block`, call `require("nginx_ui_appsec").init()` before
workers drop privileges. Do not assert success when AppSec is unconfigured:
the default mode is off. Reload Nginx after provisioning/changing the runtime
configuration or key. Keys are read once, are never logged and may remain 0600.

Server-owned `/etc/crowdsec/bouncers/nginx-ui-appsec.json`:

```json
{
  "block_url": "http://nginx-security-engine.nginx-ui.svc.cluster.local:7422",
  "detection_url": "http://nginx-security-engine.nginx-ui.svc.cluster.local:7423",
  "key_file": "/etc/crowdsec/bouncers/nginx-ui-appsec.key"
}
```

The raw key file contains an authenticated CrowdSec bouncer key. Distinct
listeners are mandatory: detection listener rules use **CancelAlert() and
CancelEvent()**, while retaining the match response. The Lua caller logs a
`detected` event and never enforces that response. Simply ignoring a 403 from
the blocking listener would allow alerts and later IP bans; it is not detection
mode. No external API endpoint is accepted; runtime URLs are restricted to
local/private/cluster-service addresses over the internal HTTP connection.
Use the full service DNS name ending `.svc.cluster.local`: the Nginx resolver
does not apply the search suffixes used by host tools.

The adapter follows CrowdSec's AppSec wire protocol and overrides the trusted
IP, host, method, URI and API-key headers. Client-supplied AppSec headers do not
select mode, identity or credentials. Request headers/body are sent only to the
private engine for inspection; structured events omit bodies, header values
and query parameters. File-backed request bodies stream in 64 KiB chunks.

Availability policy: connect/send/read timeouts are 100/250/500 ms. Bodies over
10 MiB, unreadable data, unavailable configuration and bad/failed responses
produce an explicit `error` event and let the request continue to independent
IP remediation. They are never recorded as successfully inspected. The response
body is capped at 16 KiB. Blocking matches return HTTP 403; engine configuration
uses the ban remediation, without interactive CAPTCHA/challenge UX.

The existing collector recognizes `NGINX_UI_APPSEC_EVENT` only from the fixed
Lua emitter at Nginx error severity (captured with the default error-log level)
and records source `crowdsec`, scenario `appsec/detection` or
`appsec/block`, actual client IP, and action `detected`, `blocked` or `error`.
It resolves the website from trusted site metadata and strips arbitrary suffix
context appended to Nginx error logs.

Verification:
- `test-appsec.sh`: bounded real Nginx/LuaJIT with mocked transport, modes,
  independent IP handling, spoofed metadata, file-backed bodies and bounds.
- `test-appsec-logging.sh`: both real security emitters survive the default
  Nginx error-log threshold and normalize into structured events.
- `test-ip-allowlist.sh`: existing IPv4/IPv6 regression suite.
- `python3 -m unittest discover -s packaging/security -p 'test_audit*.py'`.
- Isolated real CrowdSec 1.8.2: `/.env` detection returns 200 plus a detected
  event and leaves alerts/decisions empty; block returns 403; off and allowlist
  bypass inspection; file-backed POST detection also succeeds.

Official references:
- https://docs.crowdsec.net/docs/contributing/specs/bouncer_appsec_specs/
- https://docs.crowdsec.net/docs/appsec/configuration_rule_management/
- https://docs.crowdsec.net/docs/appsec/hooks/
