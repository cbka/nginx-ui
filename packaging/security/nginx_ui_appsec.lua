-- Per-site AppSec transport. Separate engine listeners guarantee detection
-- requests never create alerts/events/decisions; ignoring a blocking response
-- alone would NOT provide detection-only semantics.
local cjson = require "cjson.safe"
local http = require "resty.http"
local M = {}
local config, loaded
local CONFIG_PATH = "/etc/crowdsec/bouncers/nginx-ui-appsec.json"
local MAX_BODY = 10 * 1024 * 1024

local function variable(name)
    local ok, value = pcall(function() return ngx.var[name] end)
    if ok then return value end
end

local function read(path, limit)
    local file = io.open(path, "rb")
    if not file then return nil end
    local value = file:read(limit + 1)
    file:close()
    if not value or #value > limit then return nil end
    return value
end

local function endpoint(value)
    if type(value) ~= "string" then return nil end
    local host, port = value:match("^http://([%w.%-]+):(%d+)/?$")
    port = tonumber(port)
    if not host or not port or port < 1 or port > 65535 then return nil end
    -- This is a server-owned cluster integration, not a user-selected URL.
    local internal = host == "localhost" or host == "127.0.0.1"
        or host:match("%.svc$") or host:match("%.svc%.cluster%.local$")
        or require("nginx_ui_ip_allowlist").matches("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", host)
    if not internal then return nil end
    return { host = host, port = port }
end

function M.init()
    if loaded then return config ~= nil end
    loaded = true
    local raw = read(CONFIG_PATH, 8192)
    local parsed = raw and cjson.decode(raw)
    if type(parsed) ~= "table" or type(parsed.key_file) ~= "string"
        or not parsed.key_file:match("^/etc/crowdsec/bouncers/[%w_%-]+%.key$") then return false end
    local block, detection = endpoint(parsed.block_url), endpoint(parsed.detection_url)
    -- Never let detection accidentally use the blocking listener.
    if not block or not detection or (block.host == detection.host and block.port == detection.port) then return false end
    local key = read(parsed.key_file, 4096)
    if not key then return false end
    key = key:gsub("%s+$", "")
    if key == "" or key:find("[%c%s]") then return false end
    config = { block = block, detection = detection, key = key }
    return true
end

local function emit(action, mode, reason)
    local site_id = variable("nginx_ui_security_site_id") or ""
    if #site_id ~= 64 or not site_id:match("^[a-f0-9]+$") then site_id = "" end
    local encoded = cjson.encode({
        source = "crowdsec", component = "appsec", site_id = site_id,
        action = action, mode = mode, reason = reason or "",
        event_time = ngx.utctime():gsub(" ", "T") .. "Z",
        transaction_id = variable("request_id") or "",
        method = ngx.req.get_method(), path = variable("uri") or "",
        client_ip = variable("remote_addr") or "",
    })
    if encoded then ngx.log(ngx.ERR, "NGINX_UI_APPSEC_EVENT ", encoded) end
end

function M.check(mode, ip)
    if mode ~= "block" and mode ~= "detection" then return end
    if not M.init() then emit("error", mode, "configuration_unavailable"); return end
    local body_file, client
    local ok, result = pcall(function()
        local headers, header_error = ngx.req.get_headers(200)
        if header_error then return "headers_unreadable" end
        local outgoing = {}
        for name, value in pairs(headers) do
            local lower = name:lower()
            -- The request never selects the source identity, credentials or mode.
            if not lower:match("^x%-crowdsec%-appsec%-") and lower ~= "host"
                and lower ~= "content-length" and lower ~= "transfer-encoding"
                and lower ~= "connection" and lower ~= "proxy-connection"
                and lower ~= "keep-alive" and lower ~= "upgrade" and lower ~= "trailer" then
                outgoing[lower] = value
            end
        end
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        local length = body and #body or 0
        if not body then
            local path = ngx.req.get_body_file()
            if path then
                body_file = io.open(path, "rb")
                if not body_file then return "body_unreadable" end
                length = body_file:seek("end")
                if not length or not body_file:seek("set", 0) then return "body_unreadable" end
                body = function() return body_file:read(65536) end
            end
        end
        if length > MAX_BODY then return "body_limit" end
        local target = config[mode]
        outgoing["host"] = target.host .. ":" .. target.port
        outgoing["x-crowdsec-appsec-api-key"] = config.key
        outgoing["x-crowdsec-appsec-ip"] = ip
        outgoing["x-crowdsec-appsec-host"] = variable("http_host") or variable("host") or ""
        outgoing["x-crowdsec-appsec-verb"] = ngx.req.get_method()
        outgoing["x-crowdsec-appsec-uri"] = variable("request_uri") or "/"
        outgoing["x-crowdsec-appsec-user-agent"] = variable("http_user_agent") or ""
        if headers["transfer-encoding"] then outgoing["x-crowdsec-appsec-transfer-encoding"] = headers["transfer-encoding"] end
        if length > 0 then outgoing["content-length"] = tostring(length) else body = nil end
        client = http.new()
        client:set_timeouts(100, 250, 500)
        local connected = client:connect({ scheme = "http", host = target.host, port = target.port })
        if not connected then return "transport_unavailable" end
        local response = client:request({ method = length > 0 and "POST" or "GET", path = "/", headers = outgoing, body = body })
        if not response then return "transport_unavailable" end
        if response.status == 200 then return "allow" end
        if response.status ~= 403 then return "invalid_response" end
        local parts, size = {}, 0
        while true do
            local chunk, err = response.body_reader(4096)
            if err then return "invalid_response" end
            if not chunk then break end
            size = size + #chunk
            if size > 16384 then return "invalid_response" end
            parts[#parts + 1] = chunk
        end
        local data = cjson.decode(table.concat(parts))
        if type(data) ~= "table" or (data.action ~= "ban" and data.action ~= "captcha" and data.action ~= "challenge") then return "invalid_response" end
        return "match"
    end)
    if body_file then body_file:close() end
    if client then client:close() end
    if not ok then emit("error", mode, "inspection_failed"); return end
    if result == "match" then
        emit(mode == "block" and "blocked" or "detected", mode)
        if mode == "block" then return ngx.exit(ngx.HTTP_FORBIDDEN) end
    elseif result ~= "allow" then
        -- Availability-preserving failure policy; visible, never silently claimed
        -- as inspected. Existing independent IP remediation still runs afterwards.
        emit("error", mode, result)
    end
end
return M
