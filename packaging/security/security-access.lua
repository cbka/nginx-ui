-- This server-owned variable is emitted by the Security Center site policy.
-- Only an explicit 0 bypasses remediation; request headers never choose policy.
if ngx.var.nginx_ui_crowdsec_enabled == "0" then
    return
end
-- Older generated policies do not declare this variable. Undefined Nginx
-- variables can throw, so missing values preserve normal enforcement.
local ok, allowlist = pcall(function() return ngx.var.nginx_ui_crowdsec_allowlist end)
if ok and require("nginx_ui_ip_allowlist").matches(allowlist, ngx.var.remote_addr) then
    return
end
require("crowdsec").Allow(ngx.var.remote_addr)
