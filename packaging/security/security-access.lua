-- Server-owned variables only: headers never select policy or bypass inspection.
local function variable(name)
    local ok, value = pcall(function() return ngx.var[name] end)
    if ok then return value end
end
local ip = ngx.var.remote_addr
local allowlist = variable("nginx_ui_crowdsec_allowlist")
if require("nginx_ui_ip_allowlist").matches(allowlist, ip) then return end

-- AppSec is independent of IP-list remediation. Older policies omit its variable
-- and remain off. Detection uses a separate engine listener with alerts/events
-- cancelled; its response is recorded locally and never enforced here.
local mode = variable("nginx_ui_appsec_mode")
if mode == "detection" or mode == "block" then
    require("nginx_ui_appsec").check(mode, ip)
end
if variable("nginx_ui_crowdsec_enabled") ~= "0" then
    -- Keep APPSEC_URL empty in the upstream bouncer config: AppSec is called once
    -- above, while this pinned upstream entrypoint handles IP decisions/captcha.
    require("crowdsec").Allow(ip)
end
