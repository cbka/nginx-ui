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
    rule=len(args)==3 and args[0]=='appsec-rules' and args[1] in ('install','activate')
    bulk=len(args)>=2 and args[0]=='bulk'
    scenario=len(args)==3 and args[0]=='scenarios' and args[1] in ('install','remove')
    method='GET' if appsec and args[1]=='status' else 'PUT' if appsec else 'POST'
    body=({'enabled':args[1]=='enable'} if method=='PUT' else {}) if appsec or reload else {'args':args}
    if rule:body={'action':args[1],'name':args[2]}
    endpoint=('/appsec/rules' if rule else '/appsec' if appsec else '/reload' if reload else '/cscli')
    if bulk:
        if args==['bulk','cancel']:endpoint='/bulk/cancel';method='POST';body={}
        elif len(args)==3 and args[1]=='preview' and args[2] in ('scenarios','appsec'):endpoint='/bulk/preview/'+args[2];method='GET';body={}
        elif len(args)==3 and args[1]=='status' and (args[2]=='current' or __import__('re').fullmatch('[a-f0-9]{32}',args[2])):endpoint='/bulk/jobs/'+args[2];method='GET';body={}
        elif len(args)==4 and args[1]=='start' and args[2] in ('scenarios','appsec') and __import__('re').fullmatch('[a-f0-9]{64}',args[3]):endpoint='/bulk/jobs';method='POST';body={'kind':args[2],'preview_id':args[3]}
        else:raise ValueError('Invalid bulk command')
    request=urllib.request.Request(base+endpoint,data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method=method)
    with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect).open(request,timeout=210 if appsec and method=='PUT' else 120 if rule or scenario or reload else 18) as r:
        data=r.read(2*1024*1024+1)
        if len(data)>2*1024*1024:raise RuntimeError('Response too large')
        value=json.loads(data)
        if rule or bulk:print(json.dumps(value))
        elif scenario and value.get('engine_reloaded') is True:print(json.dumps({'engine_reloaded':True}))
        elif appsec:print(json.dumps(value))
        elif not reload:sys.stdout.write(value['stdout'])
except urllib.error.HTTPError as error:
    if rule or scenario or bulk:
        try:
            value=json.loads(error.read(8192))
            message=value.get('message','Engine rejected the operation')
            if not isinstance(message,str) or len(message)>256:raise ValueError()
            print(json.dumps({'operation_error':message}));sys.exit(0)
        except (ValueError,TypeError):pass
    print('Central CrowdSec operation failed',file=sys.stderr);sys.exit(1)
except Exception:
    print('Central CrowdSec operation failed',file=sys.stderr);sys.exit(1)
