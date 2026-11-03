#!/usr/bin/env python3
"""Fixed executable bridge from plugin cscli/reload calls to the central engine."""
import json,os,pathlib,sys,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise RuntimeError('Redirect refused')
try:
    base=os.environ['SECURITY_CENTER_CONTROL_URL'].rstrip('/')
    token=pathlib.Path(os.environ['SECURITY_CENTER_CONTROL_TOKEN_FILE']).read_text().strip()
    reload=pathlib.Path(sys.argv[0]).name=='crowdsec-reload'
    body={} if reload else {'args':sys.argv[1:]}
    request=urllib.request.Request(base+('/reload' if reload else '/cscli'),data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect).open(request,timeout=18) as r:
        data=r.read(2*1024*1024+1)
        if len(data)>2*1024*1024:raise RuntimeError('Response too large')
        value=json.loads(data)
        if not reload:sys.stdout.write(value['stdout'])
except Exception:
    print('Central CrowdSec operation failed',file=sys.stderr);sys.exit(1)
