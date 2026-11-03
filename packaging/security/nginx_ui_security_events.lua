-- Instrument actual remediation entrypoints of the pinned upstream bouncer.
-- Logging occurs before ngx.exit/redirect; an application HTTP 403 is not an event.
local M = {}
local installed = false
local cjson = require "cjson.safe"
local function emit(action)
    local site_id = ngx.var.nginx_ui_security_site_id
    if not site_id or not site_id:match("^[a-f0-9]+$") or #site_id ~= 64 then
        site_id = "" -- do not guess a site from Host/server_name
    end
    local record = {
        source = "crowdsec", site_id = site_id, action = action,
        event_time = ngx.utctime():gsub(" ", "T") .. "Z",
        transaction_id = ngx.var.request_id or "",
        method = ngx.req.get_method(), path = ngx.var.uri or "",
        client_ip = ngx.var.remote_addr or "",
    }
    local encoded = cjson.encode(record)
    if encoded then ngx.log(ngx.WARN, "NGINX_UI_SECURITY_EVENT ", encoded) end
end
function M.install()
    if installed then return end
    installed = true
    for _, action in ipairs({"ban", "captcha", "challenge"}) do
        local module = require("plugins.crowdsec." .. action)
        local apply = assert(module.apply, "Missing pinned CrowdSec remediation entrypoint")
        module.apply = function(...)
            emit(action)
            return apply(...)
        end
    end
end
return M
