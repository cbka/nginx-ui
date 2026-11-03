-- This server-owned variable is emitted by the Security Center site policy.
-- Only an explicit 0 bypasses remediation; request headers never choose policy.
if ngx.var.nginx_ui_crowdsec_enabled == "0" then
    return
end
require("crowdsec").Allow(ngx.var.remote_addr)
