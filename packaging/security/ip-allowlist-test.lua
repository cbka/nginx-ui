-- Load the shipped bouncer parser first to catch shared FFI declarations.
require("plugins.crowdsec.iputils")
local matcher = require('nginx_ui_ip_allowlist')
local cases = {
    {'192.0.2.0/24', '192.0.2.42', true},
    {'192.0.2.0/24', '192.0.3.42', false},
    {'192.0.2.128/25', '192.0.2.127', false},
    {'192.0.2.128/25', '192.0.2.128', true},
    {'192.0.2.42/32', '192.0.2.43', false},
    {'192.0.2.42', '192.0.2.42', true},
    {'0.0.0.0/0', '203.0.113.1', true},
    {'0.0.0.0/0', '2001:db8::1', false},
    {'2001:db8::/32', '2001:db8:ffff::1', true},
    {'2001:db8::/32', '2001:db9::1', false},
    {'2001:db8::/127', '2001:db8::1', true},
    {'2001:db8::/127', '2001:db8::2', false},
    {'::1/128', '::1', true},
    {'::/0', '2001:db8::1', true},
    {'::/0', '192.0.2.1', false},
    {'192.0.2.0/24', '::ffff:192.0.2.1', true},
    {'::ffff:192.0.2.0/120', '192.0.2.1', false},
    {'192.0.2.1,2001:db8::/32', '2001:db8::1', true},
    {'192.0.2.1,invalid', '192.0.2.1', false},
    {'192.0.2.1,,2001:db8::/32', '192.0.2.1', false},
    {',192.0.2.1', '192.0.2.1', false},
    {'192.0.2.1,', '192.0.2.1', false},
    {'192.0.2.1/33', '192.0.2.1', false},
    {'::/129', '::1', false},
    {'0.0.0.0/-1', '192.0.2.1', false},
    {'0.0.0.0/0', 'bad', false},
    {'0.0.0.0/0', '192.0.2.1\0evil', false},
    {'0.0.0.0/0', '192.0.2.1,127.0.0.1', false},
    {'', '192.0.2.1', false},
}
for i, case in ipairs(cases) do assert(matcher.matches(case[1], case[2]) == case[3], 'case ' .. i) end
assert(not matcher.matches(nil, '192.0.2.1'))
-- Exercise the real access hook with a stub bouncer. Only the resolved peer IP
-- may bypass; a spoofed header must never affect the decision.
local calls = 0
package.loaded.crowdsec = {Allow = function(ip) calls = calls + 1; assert(ip == '192.0.2.1') end}
local real_ngx = ngx
_G.ngx = {var = {remote_addr = '192.0.2.1', nginx_ui_crowdsec_enabled = '1', nginx_ui_crowdsec_allowlist = '198.51.100.0/24', http_x_forwarded_for = '198.51.100.1'}}
dofile('/test/security-access.lua'); assert(calls == 1)
ngx.var.nginx_ui_crowdsec_allowlist = '192.0.2.0/24'
dofile('/test/security-access.lua'); assert(calls == 1)
ngx.var.nginx_ui_crowdsec_allowlist = nil
setmetatable(ngx.var, {__index = function(_, key) if key == 'nginx_ui_crowdsec_allowlist' then error('unknown variable') end end})
dofile('/test/security-access.lua'); assert(calls == 2)
ngx.var.nginx_ui_crowdsec_enabled = '0'
dofile('/test/security-access.lua'); assert(calls == 2)
_G.ngx = real_ngx
ngx.say('PASS: ' .. #cases .. ' CIDR cases, missing variable, spoofed header, plugin/site disable')
