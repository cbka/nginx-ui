local emitted, captures, ip_calls, exits = {}, {}, 0, {}
local status, action, fail, body, body_path = 200, 'ban', false, nil, nil
package.loaded['resty.http'] = {new = function()
    return {
        set_timeouts = function() end,
        connect = function(_, options) captures.target = options; return not fail end,
        close = function() end,
        request = function(_, request)
            captures.request = request
            if type(request.body) == 'function' then
                local chunks = {}; while true do local c = request.body(); if not c then break end; chunks[#chunks+1] = c end
                captures.body = table.concat(chunks)
            else captures.body = request.body end
            local done = false
            return {status=status,body_reader=function()
                if done then return nil end; done=true
                return '{"action":"'..action..'"}'
            end}
        end,
    }
end}
package.loaded.crowdsec = {Allow = function() ip_calls = ip_calls + 1 end}
local real_ngx = ngx
local fake = {
    var={remote_addr='192.0.2.7',http_host='site.example',request_uri='/private?q=secret',uri='/private',
         request_id='rid',nginx_ui_security_site_id=string.rep('a',64),nginx_ui_crowdsec_enabled='0'},
    req={get_method=function()return 'POST'end,read_body=function()end,get_body_data=function()return body end,
         get_body_file=function()return body_path end,
         get_headers=function() return {['x-crowdsec-appsec-ip']='spoof', ['x-crowdsec-appsec-api-key']='forged',
             ['x-request-id']='client-forged', ['X-Request-ID']='client-mixed-case', ['x-crowdsec-appsec-host']='forged.example',['transfer-encoding']='chunked',['content-length']='999'} end},
    utctime=function()return '2026-11-04 01:00:00'end,
    log=function(_, marker, value) emitted[#emitted+1]={marker,value} end,
    WARN=4,ERR=3,HTTP_FORBIDDEN=403,
    exit=function(code) exits[#exits+1]=code; error({exit=code}) end,
}
_G.ngx = fake
local function run(mode)
    fake.var.nginx_ui_appsec_mode=mode
    local ok, err=pcall(dofile,'/test/security-access.lua')
    if not ok then assert(type(err)=='table'and err.exit==403) end
end
run(nil); assert(ip_calls==0 and #emitted==0)
fake.var.nginx_ui_crowdsec_enabled='1';run('off');assert(ip_calls==1 and #emitted==0)
fake.var.nginx_ui_crowdsec_enabled='0';run('detection');assert(captures.target.port==7423 and #emitted==0)
status=403;run('detection');assert(#exits==0 and emitted[#emitted][2]:find('detected',1,true))
assert(captures.request.headers['x-crowdsec-appsec-ip']=='192.0.2.7')
assert(captures.request.headers['x-crowdsec-appsec-api-key']=='test-only-key')
assert(captures.request.headers['x-crowdsec-appsec-host']=='site.example')
assert(captures.request.headers['x-request-id']=='rid', 'AppSec must receive server-generated request ID')
assert(captures.request.headers['X-Request-ID']==nil)
assert(not emitted[#emitted][2]:find('secret',1,true))
run('block');assert(captures.target.port==7422 and exits[#exits]==403)
fake.var.nginx_ui_crowdsec_allowlist='192.0.2.0/24';local n=#emitted;run('block');assert(#emitted==n and #exits==1)
fake.var.nginx_ui_crowdsec_allowlist='';fail=true;fake.var.nginx_ui_crowdsec_enabled='1'
run('block');assert(ip_calls==2 and #exits==1 and emitted[#emitted][2]:find('transport_unavailable',1,true))
fail=false;status=401;run('detection');assert(ip_calls==3 and emitted[#emitted][2]:find('invalid_response',1,true))
status=200;body='abc';run('detection');assert(captures.request.headers['content-length']=='3'and captures.body=='abc')
assert(not captures.request.headers['transfer-encoding'])
body=nil;body_path='/tmp/spooled-body';run('block');assert(captures.body=='file-backed-body'and captures.request.headers['content-length']=='16')
body_path=nil;body=string.rep('x',10*1024*1024+1);run('block');assert(emitted[#emitted][2]:find('body_limit',1,true))
-- An incoming header cannot choose mode. Unknown server mode does not inspect.
body=nil;local calls=ip_calls;run('invalid');assert(ip_calls==calls+1)
_G.ngx=real_ngx
ngx.say('PASS AppSec modes, independent IP remediation, trusted metadata, allowlist, fail-open, memory/file bodies, body bound')
