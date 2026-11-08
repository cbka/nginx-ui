-- One server-generated reference per HTTP request; never trust request headers.
local M = {}
local MAX_HTML = 65536
local function reference()
    local value = ngx.var.request_id
    if type(value) == "string" and #value == 32 and value:match("^[a-f0-9]+$") then return value end
end
function M.header()
    local id = reference()
    if not id then return end
    ngx.header["X-Request-ID"] = id
    local status = ngx.status
    if status ~= 401 and status ~= 403 and (status < 500 or status > 599) then return end
    local content_type = ngx.header["Content-Type"]
    -- JSON/API and other non-HTML responses keep their original body and type.
    if content_type and content_type:lower():match("^%s*([^;%s]+)") ~= "text/html" then return end
    local encoded = ngx.header["Content-Encoding"]
    -- Do not corrupt or replace already encoded application responses.
    if encoded and encoded ~= "identity" then return end
    ngx.ctx.nginx_ui_request_reference = {id = id, chunks = {}, size = 0, native = not ngx.var.upstream_status or ngx.var.upstream_status == ""}
    ngx.header["Content-Length"] = nil
    ngx.header["ETag"] = nil
    ngx.header["Content-MD5"] = nil
    ngx.header["Last-Modified"] = nil
    ngx.header["Accept-Ranges"] = nil
    ngx.header["Cache-Control"] = "no-store"
    if not content_type then ngx.header["Content-Type"] = "text/html; charset=utf-8" end
end
function M.body()
    local state = ngx.ctx.nginx_ui_request_reference
    if not state then return end
    local chunk, eof = ngx.arg[1] or "", ngx.arg[2]
    state.size = state.size + #chunk
    if state.size > MAX_HTML then
        -- Preserve oversized application errors and stop buffering. The header
        -- remains authoritative even when we cannot safely annotate the body.
        ngx.arg[1] = table.concat(state.chunks) .. chunk
        ngx.ctx.nginx_ui_request_reference = nil
        return
    end
    state.chunks[#state.chunks + 1] = chunk
    if not eof then ngx.arg[1] = nil; return end
    chunk = table.concat(state.chunks)
    if state.native then
        -- Exact native footer only, never rewrite arbitrary upstream branding.
        chunk = chunk:gsub("<hr><center>nginx/?[%d%.]*</center>\r?\n?", "")
    end
    -- A chained Nginx UI proxy may already have annotated this HTML. Replace
    -- only our exact generated block; unrelated application markup is retained.
    chunk = chunk:gsub('<div role="note" class="nginx%-ui%-request%-reference"><p>Referenz%-ID: <code>([a-f0-9]+)</code></p></div>', function(old_id)
        if #old_id == 32 then return "" end
        return '<div role="note" class="nginx-ui-request-reference"><p>Referenz-ID: <code>' .. old_id .. '</code></p></div>'
    end)
    local block = '<div role="note" class="nginx-ui-request-reference"><p>Referenz-ID: <code>' .. state.id .. '</code></p></div>'
    local before, closing = chunk:match("^(.*)(</[bB][oO][dD][yY]%s*>.*)$")
    if before then
        chunk = before .. block .. closing
    elseif not chunk:find("<", 1, true) then
        -- Plain text served as HTML (e.g. an explicit return) has no open tags.
        chunk = chunk .. block
    end
    ngx.arg[1] = chunk
    ngx.ctx.nginx_ui_request_reference = nil
end
return M
