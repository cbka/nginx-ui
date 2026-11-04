-- Exercise both real emitters with the default Nginx error-log threshold.
package.loaded['resty.http'] = {new=function() return {
    set_timeouts=function() end,connect=function()return true end,close=function()end,
    request=function() local done=false;return {status=403,body_reader=function()
        if done then return nil end;done=true;return '{"action":"ban"}'
    end} end,
} end}
require('nginx_ui_appsec').check('detection', ngx.var.remote_addr)
for _, action in ipairs({'ban','captcha','challenge'}) do
    package.loaded['plugins.crowdsec.'..action]={apply=function()end}
end
require('nginx_ui_security_events').install()
require('plugins.crowdsec.ban').apply()
ngx.say('ok')
