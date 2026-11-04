#!/usr/bin/env python3
"""Fixed executable bridge from plugin cscli/reload calls to the central engine."""
import json,os,pathlib,sys,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise RuntimeError('Redirect refused')
try:
    base=os.environ['SECURITY_CENTER_CONTROL_URL'].rstrip('/')
    token=pathlib.Path(os.environ['SECURITY_CENTER_CONTROL_TOKEN_FILE']).read_text().strip()
    reload=pathlib.Path(sys.argv[0]).name=='crowdsec-reload'
    args=sys.argv[1:]
    appsec=args in [['appsec','status'],['appsec','enable'],['appsec','disable']]
    method='GET' if appsec and args[1]=='status' else 'PUT' if appsec else 'POST'
    body=({'enabled':args[1]=='enable'} if method=='PUT' else {}) if appsec or reload else {'args':args}
    request=urllib.request.Request(base+('/appsec' if appsec else '/reload' if reload else '/cscli'),data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method=method)
    with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect).open(request,timeout=210 if appsec and method=='PUT' else 18) as r:
        data=r.read(2*1024*1024+1)
        if len(data)>2*1024*1024:raise RuntimeError('Response too large')
        value=json.loads(data)
        if appsec:print(json.dumps(value))
        elif not reload:sys.stdout.write(value['stdout'])
except Exception:
    print('Central CrowdSec operation failed',file=sys.stderr);sys.exit(1)
