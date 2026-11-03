-- Compare only Nginx's resolved client address, never a request header.
local ffi = require("ffi")
ffi.cdef[[int inet_pton(int af, const char *src, void *dst);]]
local M = {}
local cache, cache_size = {}, 0

local function address(value)
    if type(value) ~= "string" or value == "" or value:find("%z") then return nil end
    local bytes = ffi.new("unsigned char[16]")
    local family, size = 2, 4
    if ffi.C.inet_pton(family, value, bytes) ~= 1 then
        family, size = 10, 16
        if ffi.C.inet_pton(family, value, bytes) ~= 1 then return nil end
    end
    -- Normalize IPv4-mapped IPv6 client addresses to their IPv4 identity.
    if family == 10 then
        local mapped = bytes[10] == 255 and bytes[11] == 255
        for i = 0, 9 do mapped = mapped and bytes[i] == 0 end
        if mapped then
            for i = 0, 3 do bytes[i] = bytes[i + 12] end
            family, size = 2, 4
        end
    end
    return { bytes = bytes, family = family, size = size }
end

local function compile(list)
    if #list > 65536 or list:sub(1, 1) == "," or list:sub(-1) == "," or list:find(",,", 1, true) then return false end
    local networks = {}
    for token in list:gmatch("[^,]+") do
        local ip, suffix = token:match("^([^/]+)/(%d+)$")
        if not ip then ip = token end
        local net = address(ip)
        if not net then return false end
        local bits = suffix and tonumber(suffix) or net.size * 8
        -- Mapped CIDRs are rejected; the API must canonicalize them as IPv4.
        if ip:find(":", 1, true) and net.family == 2 then return false end
        if not bits or bits > net.size * 8 then return false end
        net.bits = bits
        networks[#networks + 1] = net
        if #networks > 1024 then return false end
    end
    return networks
end

function M.matches(list, client)
    if type(list) ~= "string" or list == "" then return false end
    local networks = cache[list]
    if networks == nil then
        networks = compile(list)
        if cache_size >= 128 then cache, cache_size = {}, 0 end
        cache[list], cache_size = networks, cache_size + 1
    end
    if not networks then return false end
    local ip = address(client)
    if not ip then return false end
    for _, net in ipairs(networks) do
        if ip.family == net.family then
            local whole, remainder = math.floor(net.bits / 8), net.bits % 8
            local match = true
            for i = 0, whole - 1 do
                if ip.bytes[i] ~= net.bytes[i] then match = false; break end
            end
            if match and remainder > 0 then
                local divisor = 2 ^ (8 - remainder)
                match = math.floor(ip.bytes[whole] / divisor) == math.floor(net.bytes[whole] / divisor)
            end
            if match then return true end
        end
    end
    return false
end
return M
