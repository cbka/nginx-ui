#!/usr/bin/env python3
"""Hourly transactional updates of installed Hub content, without activation changes."""
import contextlib, datetime, fcntl, hashlib, json, os, pathlib, shutil, tempfile, threading, time

INTERVAL = 3600
STATUS = pathlib.Path('/var/lib/crowdsec/data/hub-update-status.json')
PROCESS_LOCK = pathlib.Path('/run/crowdsec-hub-update.lock')
ACTIVE_DIRS = ('collections', 'scenarios', 'parsers', 'postoverflows', 'contexts', 'appsec-configs', 'appsec-rules')

def atomic_status(value):
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=STATUS.parent, prefix='.hub-update-')
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, indent=2); out.flush(); os.fsync(out.fileno())
        os.replace(name, STATUS)
    finally:
        if os.path.exists(name): os.unlink(name)

def read_status():
    try:
        if STATUS.stat().st_size > 2*1024*1024: return {}
        value=json.loads(STATUS.read_text())
        return value if isinstance(value,dict) else {}
    except (OSError, ValueError): return {}

def installed_versions(value):
    """Keep only public Hub inventory names/versions, never arbitrary CLI payloads."""
    result=[]
    def visit(node, kind=''):
        if len(result)>4000: raise ValueError('Hub inventory exceeds limit')
        if isinstance(node, list):
            for child in node: visit(child,kind)
        elif isinstance(node,dict):
            if isinstance(node.get('name'),str):
                result.append({'kind':kind,'name':node['name'][:256],
                  'version':str(node.get('local_version',node.get('version','unknown')))[:128]})
            else:
                for key, child in node.items(): visit(child,str(key)[:64])
    visit(value)
    return sorted(result,key=lambda item:(item['kind'],item['name']))

def active_fingerprint(root):
    digest=hashlib.sha256()
    total=0
    for name in ACTIVE_DIRS:
        directory=root/name
        if not directory.exists():continue
        for path in sorted(directory.rglob('*')):
            if path.is_file():
                size=path.stat().st_size;total+=size
                if total>64*1024*1024:raise RuntimeError('Active rules exceed fingerprint limit')
                digest.update(str(path.relative_to(root)).encode());digest.update(b'\0')
                with path.open('rb') as file:
                    while chunk:=file.read(65536):digest.update(chunk)
                digest.update(b'\0')
    return digest.hexdigest()

def dataset_files(control):
    value=control.config()
    directory=pathlib.Path(value.get('config_paths',{}).get('data_dir','/var/lib/crowdsec/data'))
    database=pathlib.Path(value.get('db_config',{}).get('db_path',directory/'crowdsec.db'))
    excluded={database.resolve(),pathlib.Path(str(database)+'-wal').resolve(),
              pathlib.Path(str(database)+'-shm').resolve(),pathlib.Path(str(database)+'-journal').resolve(),STATUS.resolve()}
    files=[];total=0
    if not directory.exists():return directory,files
    for path in sorted(directory.rglob('*')):
        if path.resolve() in excluded or path.name.startswith('.hub-update-'):continue
        if not path.is_file():continue
        if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
            raise RuntimeError('Dataset must be a regular file inside data directory')
        total+=path.stat().st_size;files.append(path)
        if len(files)>20000 or total>64*1024*1024:raise RuntimeError('Dataset snapshot exceeds limit')
    return directory,files

def dataset_fingerprint(control):
    directory,files=dataset_files(control)
    digest=hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(directory)).encode());digest.update(b'\0')
        with path.open('rb') as file:
            while chunk:=file.read(65536):digest.update(chunk)
        digest.update(b'\0')
    return digest.hexdigest()

@contextlib.contextmanager
def dataset_snapshot(control):
    directory,files=dataset_files(control)
    backup=pathlib.Path(tempfile.mkdtemp(prefix='crowdsec-dataset-rollback-'))
    preserve=False
    try:
        for path in files:
            target=backup/path.relative_to(directory);target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(path,target)
        def restore():
            nonlocal preserve
            try:
                _,current=dataset_files(control)
                for path in current:path.unlink()
                for path in backup.rglob('*'):
                    if path.is_file():
                        target=directory/path.relative_to(backup);target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copy2(path,target)
            except Exception:
                preserve=True
                print('CrowdSec dataset rollback failed; private recovery snapshot: '+str(backup),flush=True)
                raise
        yield restore
    finally:
        if not preserve:shutil.rmtree(backup)

def virtual_patch_dependencies(index):
    item=index.get('collections',{}).get('crowdsecurity/appsec-virtual-patching',{})
    return {(kind,name) for kind in ACTIVE_DIRS for name in item.get(kind,[])
            if isinstance(name,str) and name.startswith('crowdsecurity/')}

def read_index(control):
    path=pathlib.Path(control.config().get('config_paths',{}).get('index_path',control.CONFIG.parent/'hub/.index.json'))
    if not path.exists():return {}
    if path.stat().st_size>32*1024*1024:raise RuntimeError('Hub index exceeds limit')
    return json.loads(path.read_text())

def upgrade(control):
    root=control.CONFIG.parent
    config_before=control.CONFIG.read_bytes()
    before_fingerprint=active_fingerprint(root)
    old_index=read_index(control)
    patch_active=(root/'collections/appsec-virtual-patching.yaml').is_file()
    before_datasets=dataset_fingerprint(control)
    with tempfile.TemporaryDirectory(prefix='crowdsec-activation-') as temp:
        backup=pathlib.Path(temp)
        existing=set()
        for name in ACTIVE_DIRS:
            path=root/name
            if path.exists():
                if path.is_symlink(): raise RuntimeError('Activation root cannot be a symlink')
                existing.add(name); shutil.copytree(path,backup/name,symlinks=True)
        control.invoke(['/usr/bin/cscli','hub','update'],timeout=180)
        control.invoke(['/usr/bin/cscli','hub','upgrade'],timeout=180)
        # Only genuinely NEW dependencies in the official virtual-patching collection
        # may become active automatically. Previously available but disabled entries
        # remain disabled; all unrelated activation sets remain exact.
        if patch_active:
            current_index=read_index(control)
            new_deps=virtual_patch_dependencies(current_index)-virtual_patch_dependencies(old_index)
            for kind,item in new_deps:
                if item in old_index.get(kind,{}):continue
                meta=current_index.get(kind,{}).get(item,{})
                remote=meta.get('path','')
                for active in (root/kind).rglob('*'):
                    if active.is_symlink() and active.resolve()==(root/'hub'/remote).resolve() and active.resolve().is_relative_to((root/'hub').resolve()):
                        dest=backup/kind/active.relative_to(root/kind)
                        dest.parent.mkdir(parents=True,exist_ok=True)
                        dest.symlink_to(os.readlink(active));existing.add(kind)
        # Upgrade may install new collection dependencies. Preserve the exact
        # enabled set (including local files) and resolve symlinks to new Hub
        # versions. Incompatible new dependencies fail validation and roll back.
        for name in existing:
            # Regular enabled files can also be Hub-managed. Retain their
            # upgraded bytes; --force is never used, so tainted local files are
            # left alone by cscli. Only the activation set is frozen.
            for before in (backup/name).rglob('*'):
                if before.is_file() and not before.is_symlink():
                    current=root/name/before.relative_to(backup/name)
                    if current.is_file() and not current.is_symlink():
                        shutil.copy2(current,before)
        for name in ACTIVE_DIRS:
            path=root/name
            if path.is_symlink(): path.unlink()
            elif path.exists(): shutil.rmtree(path)
            if name in existing: shutil.copytree(backup/name,path,symlinks=True)
        if control.CONFIG.read_bytes()!=config_before:
            raise RuntimeError('Hub update changed engine configuration')
        index=pathlib.Path(control.config().get('config_paths',{}).get('index_path',root/'hub/.index.json'))
        if index.stat().st_size>32*1024*1024: raise RuntimeError('Hub index exceeds limit')
        version=hashlib.sha256(index.read_bytes()).hexdigest()
        inventory=json.loads(control.invoke(['/usr/bin/cscli','hub','list','-o','json']))
        return {'hub_index_sha256':version,'installed_versions':installed_versions(inventory),
                'changed':active_fingerprint(root)!=before_fingerprint or dataset_fingerprint(control)!=before_datasets}

def run_once(control):
    """False means another UI mutation/update owns the lock; retry next minute."""
    if not control.LOCK.acquire(blocking=False): return False
    try:
        PROCESS_LOCK.parent.mkdir(parents=True,exist_ok=True)
        with PROCESS_LOCK.open('a') as lock:
            try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: return False
            previous=read_status()
            result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'last_attempt_epoch':time.time(),'interval_seconds':INTERVAL,
                    'last_success_at':previous.get('last_success_at'),
                    'version':previous.get('version')}
            try:
                with dataset_snapshot(control) as restore_datasets:
                    version=control.configuration_transaction(lambda:upgrade(control),
                        reload_required=lambda result:result['changed'],rollback_extra=restore_datasets)
                changed=version.pop('changed')
                result.update(status='success',last_success_at=result['checked_at'],version=version,changed=changed)
            except Exception as error:
                # Do not leak command output, config contents or private paths.
                result.update(status='failure',message='Hub update failed; inspect engine logs and recovery state',
                    error_type=type(error).__name__,recovery_required='manual recovery required' in str(error))
            atomic_status(result)
            print(json.dumps({'component':'crowdsec-hub-update','status':result['status'],
                'changed':result.get('changed',False),'error_type':result.get('error_type'),
                'recovery_required':result.get('recovery_required',False)}),flush=True)
            return True
    finally: control.LOCK.release()

def scheduler(control, stop=None):
    stop=stop or threading.Event()
    # Let initial engine startup/SQLite migration complete before checking Hub.
    if stop.wait(60): return
    while not stop.is_set():
        previous=read_status()
        last=previous.get('last_attempt_epoch',0)
        if not isinstance(last,(int,float)):last=0
        if time.time()-last>=INTERVAL:
            try: run_once(control)
            except Exception: print('CrowdSec Hub update status unavailable',flush=True)
        stop.wait(60)
