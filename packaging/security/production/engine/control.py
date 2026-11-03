#!/usr/bin/env python3
"""Private, token-authenticated fixed CrowdSec operations; never accepts shell commands."""
import shutil, stat, sys
import hmac, http.server, ipaddress, json, os, pathlib, re, socket, subprocess, tempfile, threading, time
CONFIG = pathlib.Path('/etc/crowdsec/config.yaml')
TOKEN = pathlib.Path('/run/secrets/control-token')
LOCK = threading.Lock()
MAX_BODY = 8192

def invoke(args, timeout=12):
    with tempfile.TemporaryFile() as out:
        result = subprocess.run(args, stdout=out, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        out.seek(0); data = out.read(2*1024*1024+1)
        if result.returncode or len(data)>2*1024*1024:
            raise RuntimeError('CrowdSec operation failed; inspect engine logs')
        return data.decode()

def allowed(args):
    if not isinstance(args,list) or not all(isinstance(x,str) and len(x)<=256 and '\x00' not in x for x in args): return False
    if args in [['decisions','list','-o','json','--limit','100','--no-simu'], ['scenarios','list','-o','json']]: return True
    if len(args)==3 and args[0]=='scenarios' and args[1] in ['install','remove']:
        return re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}/[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}',args[2]) is not None
    if len(args)==4 and args[:3]==['decisions','delete','--id']:
        return args[3].isdigit() and 0<int(args[3])<2**64
    if len(args)==10 and args[:3]==['decisions','add','--ip'] and args[4]=='--duration' and args[6]=='--reason' and args[8:]==['--type','ban']:
        try: ipaddress.ip_address(args[3])
        except ValueError: return False
        return re.fullmatch(r'[1-9][0-9]{0,4}[smh]',args[5]) is not None and bool(args[7]) and not any(ord(c)<32 for c in args[7])
    return False

def config():
    value=json.loads(CONFIG.read_text())
    if type(value['api']['server']['online_client']['sharing']) is not bool:
        raise ValueError('Sharing must be an explicit boolean')
    return value

def control_token():
    value=TOKEN.read_text().strip()
    if not re.fullmatch(r'[a-f0-9]{64}',value):raise ValueError('Invalid control token')
    return value
def atomic(value):
    fd,tmp=tempfile.mkstemp(dir=CONFIG.parent,prefix='.control-')
    try:
        with os.fdopen(fd,'w') as f: json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(tmp,CONFIG)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def engine_ready():
    try:
        with socket.create_connection(('127.0.0.1',8080),1): return True
    except OSError:return False

def reload_engine():
    invoke(['/usr/local/bin/crowdsec','-c',str(CONFIG),'-t','-no-capi'],6)
    invoke(['supervisorctl','-c','/etc/supervisor/engine.conf','restart','crowdsec'],6)
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        if engine_ready():return
        time.sleep(.2)
    raise RuntimeError('Engine restart did not become ready')

def sharing():
    enabled=config()['api']['server']['online_client']['sharing']
    mode=pathlib.Path('/run/crowdsec-mode.json')
    verified=engine_ready() and mode.exists() and json.loads(mode.read_text()).get('sharing')==enabled
    return dict(configured=True,enabled=enabled,editable=True,runtime_verified=verified,message='Central engine setting. Sharing sends engine alerts, not every blocked request. Community sharing is disabled unless explicitly enabled.')

def set_sharing(enabled):
    old=config(); value=json.loads(json.dumps(old))
    if enabled:
        credentials=pathlib.Path('/etc/crowdsec/online_api_credentials.yaml')
        if not credentials.exists() or credentials.stat().st_size<10:
            # Only the explicit authenticated enable action may enroll with CAPI.
            invoke(['/usr/bin/cscli','capi','register'],12)
    value['api']['server']['online_client']['sharing']=enabled
    atomic(value)
    try:reload_engine()
    except Exception:
        atomic(old)
        reload_engine()
        raise
    return sharing()

def scenario_change(args):
    """Transactional config/activation update; data downloads remain inert caches.

    Never snapshot or replace the live data_dir/SQLite database. New downloaded
    datasets can remain after rollback, but restored configuration does not use
    newly installed scenarios. The handler's LOCK serializes all control writes.
    """
    if not allowed(args) or len(args)!=3 or args[:2] not in [['scenarios','install'],['scenarios','remove']]:
        raise ValueError('Unsupported scenario operation')
    return configuration_transaction(lambda: invoke(['/usr/bin/cscli',*args]))

def configuration_transaction(operation, reload_required=lambda result: True, rollback_extra=lambda: None):
    """Caller holds LOCK; snapshot config only, then validate/reload or restore."""
    value=config()
    root=CONFIG.parent
    if root.is_symlink():raise RuntimeError('Config root must not be a symlink')
    paths=value.get('config_paths',{})
    for key in ('config_dir','hub_dir','index_path'):
        if key in paths and not pathlib.Path(paths[key]).resolve().is_relative_to(root.resolve()):
            raise RuntimeError('Scenario configuration paths must stay inside config root')
    # No arbitrary special files, unbounded tree, or live DB inside this snapshot.
    size=count=0
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            path=pathlib.Path(directory)/name; info=path.lstat(); count+=1
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise RuntimeError('Unsupported configuration file type')
            if stat.S_ISLNK(info.st_mode) and not path.resolve().is_relative_to(root.resolve()):
                raise RuntimeError('Configuration symlink escapes snapshot root')
            if stat.S_ISREG(info.st_mode):size+=info.st_size
            if count>20000 or size>64*1024*1024:raise RuntimeError('Configuration snapshot exceeds safety limit')
    data_dir=paths.get('data_dir')
    if data_dir and pathlib.Path(data_dir).resolve().is_relative_to(root.resolve()):
        raise RuntimeError('Live data directory cannot be included in config snapshot')
    backup=pathlib.Path(tempfile.mkdtemp(prefix='crowdsec-config-rollback-'))
    preserve=False
    try:
        shutil.copytree(root,backup/'config',symlinks=True)
        try:
            output=operation()
            if reload_required(output): reload_engine()
            return output
        except Exception:
            try:
                for path in root.iterdir():
                    if path.is_dir() and not path.is_symlink():shutil.rmtree(path)
                    else:path.unlink()
                shutil.copytree(backup/'config',root,symlinks=True,dirs_exist_ok=True)
                rollback_extra()
                reload_engine()
            except Exception:
                preserve=True
                print('CrowdSec scenario rollback failed; private recovery snapshot: '+str(backup),file=sys.stderr)
                raise RuntimeError('Scenario rollback failed; manual recovery required') from None
            raise RuntimeError('Scenario operation failed; previous configuration restored') from None
    finally:
        if not preserve:shutil.rmtree(backup)

class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)
    def log_message(self,*args):pass
    def send(self,code,value):
        data=json.dumps(value).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def handle_request(self):
        try:expected='Bearer '+control_token()
        except (OSError,ValueError):return self.send(503,{'message':'Control authentication unavailable'})
        if not hmac.compare_digest(self.headers.get('Authorization',''),expected):return self.send(401,{'message':'Unauthorized'})
        if self.headers.get('Transfer-Encoding'):return self.send(400,{'message':'Invalid body'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=MAX_BODY:raise ValueError()
            body=json.loads(self.rfile.read(length)) if length else {}
            with LOCK:
                if self.command=='GET' and self.path=='/sharing':result=sharing()
                elif self.command=='GET' and self.path=='/hub-updates':
                    import hub_update
                    result=hub_update.read_status()
                elif self.command=='PUT' and self.path=='/sharing' and isinstance(body,dict) and set(body)=={'enabled'} and type(body['enabled']) is bool:result=set_sharing(body['enabled'])
                elif self.command=='POST' and self.path=='/reload' and body=={}:reload_engine();result={'reloaded':True}
                elif self.command=='POST' and self.path=='/cscli' and isinstance(body,dict) and set(body)=={'args'} and allowed(body['args']):
                    args=body['args']
                    result={'stdout':scenario_change(args) if args[:2] in [['scenarios','install'],['scenarios','remove']] else invoke(['/usr/bin/cscli',*args])}
                else:return self.send(400,{'message':'Unsupported operation'})
            self.send(200,result)
        except (ValueError,TypeError,KeyError):self.send(400,{'message':'Invalid request or engine configuration'})
        except Exception:self.send(502,{'message':'Engine operation failed; verify current engine state before retrying'})
    do_GET=handle_request
    do_PUT=handle_request
    do_POST=handle_request

if __name__=='__main__':
    os.umask(0o077)
    control_token()
    import hub_update
    threading.Thread(target=hub_update.scheduler,args=(sys.modules[__name__],),daemon=True,name='hub-updates').start()
    server=http.server.HTTPServer(('0.0.0.0',8081),Handler)
    server.timeout=15
    server.serve_forever()
