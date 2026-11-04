"""Private AppSec inventory and explicit, transactional virtual-patching bootstrap."""
import json, os, socket, tempfile, time

COLLECTION = 'crowdsecurity/appsec-virtual-patching'
LISTEN = '0.0.0.0:7422'
ACQUISITION = {'source':'appsec','name':'nginx-ui-appsec','listen_addr':LISTEN,
               'appsec_configs':['crowdsecurity/virtual-patching'],'labels':{'type':'appsec'}}

DETECTION = dict(ACQUISITION, name='nginx-ui-appsec-detection', listen_addr='0.0.0.0:7423', appsec_configs=['custom/nginx-ui-detection'])
DETECTION_CONFIG = {'name':'custom/nginx-ui-detection','default_remediation':'ban',
 'inband_rules':['crowdsecurity/base-config','crowdsecurity/vpatch-*'],
 'on_match':[{'apply':['CancelAlert()','CancelEvent()']}]}

def acquisition_path(control):
    return control.CONFIG.parent/'acquis.d/nginx-ui-appsec.yaml'

def rows(control, kind):
    payload=json.loads(control.invoke(['/usr/bin/cscli',kind,'list','-a','-o','json']))
    values=payload.get(kind,[]) if isinstance(payload,dict) else payload
    if not isinstance(values,list) or len(values)>4000:raise ValueError('Invalid AppSec inventory')
    result=[]
    for item in values:
        if not isinstance(item,dict) or not isinstance(item.get('name'),str):raise ValueError('Invalid Hub entry')
        status=str(item.get('status',''))
        flags={s.strip() for s in status.split(',')}
        result.append({'name':item['name'][:256],'description':str(item.get('description',''))[:2048],
                       'version':str(item.get('local_version',''))[:128], 'status':status[:256],
                       'available':'local' not in flags, 'installed':'enabled' in flags,
                       'update_available':'update-available' in flags,
                       'tainted':'tainted' in flags, 'loaded':None,
                       'editable':kind=='appsec-rules' and supported_rule(item['name']) and 'local' not in flags and 'tainted' not in flags})
    return result

def managed_files(control):
    path=acquisition_path(control)
    return {path:ACQUISITION,path.with_name('nginx-ui-appsec-detection.yaml'):DETECTION,
            control.CONFIG.parent/'appsec-configs/nginx-ui-detection.yaml':DETECTION_CONFIG}

def enabled(control):
    complete=True
    for path,expected in managed_files(control).items():
        if path.is_symlink():raise ValueError('Managed AppSec path is a symlink')
        if not path.exists():complete=False;continue
        if not path.is_file() or path.stat().st_size>8192:raise ValueError('Unmanaged AppSec configuration')
        if json.loads(path.read_text())!=expected:raise ValueError('Unmanaged AppSec configuration')
    return complete

def ready(port=7422):
    try:
        with socket.create_connection(('127.0.0.1',port),.3):return True
    except OSError:return False

def inventory(control):
    active=enabled(control)
    rules=rows(control,'appsec-rules')
    verified=runtime_verified(control)
    for rule in rules:rule['editable']=rule.get('editable',False) and active
    if verified:
        for rule in rules:
            if rule['installed'] and (rule['name']=='crowdsecurity/base-config' or rule['name'].startswith('crowdsecurity/vpatch-')):
                rule['loaded']=True
    return {'enabled':active,'ready':active and ready(),'listen_addr':LISTEN,
            'detection_listen_addr':'0.0.0.0:7423','detection_ready':active and ready(7423),
            'runtime_load_verified':verified,
            'configs':rows(control,'appsec-configs'),
            'collections':[r for r in rows(control,'collections') if r['name']==COLLECTION],
            'rules':rules,'rule_count':sum(r['installed'] for r in rules)}

def set_enabled(control, value):
    """Caller holds control.LOCK. No CAPI enrollment, sharing changes, or force installs."""
    if type(value) is not bool:raise ValueError('Boolean required')
    configured=control.config().get('crowdsec_service',{}).get('acquisition_dir')
    if configured and os.path.realpath(configured)!=str((control.CONFIG.parent/'acquis.d').resolve()):
        raise ValueError('Engine acquisition directory does not match managed listener path')
    previous=enabled(control)
    has_acquisition=any(p.exists() for p in managed_files(control) if p.parent.name=='acquis.d')
    if previous==value and (value or not has_acquisition):return {'enabled':value,'changed':False,'ready':value and ready()}
    path=acquisition_path(control)
    original=control.CONFIG.read_bytes()
    def operation():
        if value:
            collections=rows(control,'collections')
            if not any(r['name']==COLLECTION and r['installed'] for r in collections):
                control.invoke(['/usr/bin/cscli','collections','install',COLLECTION],timeout=180)
            path.parent.mkdir(exist_ok=True)
            detection=path.with_name('nginx-ui-appsec-detection.yaml')
            detection.write_text(json.dumps(DETECTION))
            custom=control.CONFIG.parent/'appsec-configs/nginx-ui-detection.yaml'
            custom.parent.mkdir(exist_ok=True)
            if custom.is_symlink():raise ValueError('Managed config cannot be symlink')
            custom.write_text(json.dumps(DETECTION_CONFIG))
            fd,name=tempfile.mkstemp(dir=path.parent,prefix='.appsec-')
            try:
                with os.fdopen(fd,'w') as out:
                    json.dump(ACQUISITION,out);out.flush();os.fsync(out.fileno())
                os.replace(name,path)
            finally:
                if os.path.exists(name):os.unlink(name)
        else:
            path.unlink(missing_ok=True)
            path.with_name('nginx-ui-appsec-detection.yaml').unlink(missing_ok=True)
        if control.CONFIG.read_bytes()!=original:raise RuntimeError('AppSec must not change engine settings')
        return {'enabled':value,'changed':True}
    # Collection dependencies may download lookup datasets. Restore these on failure
    # before recovering the old engine, without touching SQLite or its journals.
    import hub_update
    with hub_update.dataset_snapshot(control) as restore:
        result=control.configuration_transaction(operation,rollback_extra=restore)
    result['ready']=value and ready()
    return result

# Receipt ties the configuration fingerprint to this exact engine process, not
# merely to persisted configuration or a listener belonging to an earlier run.
START_RECEIPT = __import__('pathlib').Path('/run/crowdsec-appsec-start.json')

def process_identity(pid):
    import pathlib
    process=pathlib.Path('/proc')/str(pid)
    # comm can contain spaces: fields after the final ')' begin with field 3.
    start_ticks=process.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
    return {'pid':pid,'start_ticks':start_ticks,
            'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}

def runtime_fingerprint(control):
    import hashlib,hub_update
    digest=hashlib.sha256(control.CONFIG.read_bytes())
    digest.update(hub_update.active_fingerprint(control.CONFIG.parent).encode())
    for path in managed_files(control):
        digest.update(str(path).encode());digest.update(path.read_bytes())
    return digest.hexdigest()

def record_start(control):
    record=process_identity(os.getpid())
    record['fingerprint']=runtime_fingerprint(control) if enabled(control) else None
    fd,name=tempfile.mkstemp(dir=START_RECEIPT.parent,prefix='.appsec-start-')
    try:
        with os.fdopen(fd,'w') as out:
            json.dump(record,out);out.flush();os.fsync(out.fileno())
        os.replace(name,START_RECEIPT)
    finally:
        if os.path.exists(name):os.unlink(name)

def runtime_verified(control):
    import pathlib
    try:
        if not enabled(control) or not ready() or not ready(7423):return False
        if START_RECEIPT.stat().st_size>4096:return False
        receipt=json.loads(START_RECEIPT.read_text())
        pid=receipt['pid']
        if type(pid) is not int or pid<=0:return False
        if any(receipt.get(k)!=v for k,v in process_identity(pid).items()):return False
        cmd=pathlib.Path('/proc',str(pid),'cmdline').read_bytes().split(b'\0')
        if not cmd or cmd[0]!=b'/usr/local/bin/crowdsec':return False
        if [b'-c',str(control.CONFIG).encode()] not in [cmd[i:i+2] for i in range(len(cmd)-1)]:return False
        return receipt.get('fingerprint')==runtime_fingerprint(control)
    except (OSError,ValueError,KeyError,TypeError,IndexError):return False


def supported_rule(name):
    import re
    return isinstance(name,str) and re.fullmatch(r'crowdsecurity/(?:base-config|vpatch-[a-zA-Z0-9_-]{1,120})',name) is not None

def change_rule(control, name, action):
    """Only rules selected by both managed virtual-patching profiles may activate."""
    if action not in ('install','activate') or not supported_rule(name):
        raise ValueError('Unsupported AppSec rule operation')
    if not enabled(control):raise ValueError('Enable the managed AppSec engine first')
    match=next((r for r in rows(control,'appsec-rules') if r['name']==name),None)
    if match is None or not match['available'] or match['tainted']:
        raise ValueError('Rule must be an unmodified official Hub entry')
    def operation():
        if not match['installed']:
            control.invoke(['/usr/bin/cscli','appsec-rules','install',name],timeout=25)
        return name
    def activate(result):
        control.reload_engine()
        deadline=time.monotonic()+30
        while not runtime_verified(control):
            if time.monotonic()>=deadline:raise RuntimeError('AppSec listeners did not become ready after reload')
            time.sleep(.2)
        if not any(r['name']==name and r['installed'] for r in rows(control,'appsec-rules')):
            raise RuntimeError('AppSec rule activation could not be verified')
        return False
    control.configuration_transaction(operation,reload_required=activate)
    return {'applied':True,'name':name,'loaded':True,'engine_reloaded':True}
