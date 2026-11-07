"""Bounded, central bulk jobs. One config transaction and one verified reload.

Job receipts live on the engine PVC, independent of browser/plugin processes.
A durable config-only recovery copy (never SQLite) protects interrupted batches.
"""
import copy,datetime,fcntl,hashlib,json,os,pathlib,re,shutil,tempfile,threading,time,uuid
import appsec
STATE=pathlib.Path('/var/lib/crowdsec/data/nginx-ui-bulk')
STATE_LOCK=threading.RLock()
ACTIVE={'queued','running','validating'}
MAX_SECONDS=600
CANCEL=threading.Event()
DISABLING=threading.Event()
CANCELLING=threading.Event()
NAME=re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}/[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}')

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def atomic(path,value):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.bulk-')
 try:
  with os.fdopen(fd,'w')as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
def current():
 with STATE_LOCK:
  p=STATE/'current.json'
  if not p.exists():return None
  if p.stat().st_size>2*1024*1024:raise ValueError('Invalid bulk receipt')
  return json.loads(p.read_text())
def save(job):
 with STATE_LOCK:
  job['updated_at']=now();atomic(STATE/'current.json',job)
def cancel():
 with STATE_LOCK:
  job=current()
  if job and job.get('state')in ACTIVE:
   CANCELLING.set();CANCEL.set()
  return job

def status(identifier):
 if identifier!='current'and not re.fullmatch('[a-f0-9]{32}',identifier):raise ValueError('Invalid bulk job')
 job=current()
 if identifier!='current'and (job is None or job['id']!=identifier):raise ValueError('Bulk job no longer retained; refresh current job')
 return job

def preview(control,kind):
 if kind not in ('scenarios','appsec'):raise ValueError('Invalid bulk kind')
 managed=appsec.enabled(control) if kind=='appsec' else True
 verified=appsec.runtime_verified(control) if kind=='appsec' and managed else False
 raw=appsec.rows(control,'scenarios' if kind=='scenarios' else 'appsec-rules')
 items=[];seen=set()
 for row in sorted(raw,key=lambda x:x['name']):
  name=row['name']
  if name in seen:raise ValueError('Duplicate Hub entry')
  seen.add(name);reason='';action='install'
  if not NAME.fullmatch(name):reason='Ungültiger Hub-Name'
  elif not row.get('available'):reason='Lokaler Eintrag; wird nicht überschrieben'
  elif row.get('tainted'):reason='Lokal geändert; wird nicht überschrieben'
  elif kind=='appsec' and not appsec.supported_rule(name):reason='Nicht vom Virtual-Patching-Profil unterstützt'
  elif kind=='appsec' and not managed:reason='AppSec-Engine ist deaktiviert'
  elif row.get('installed'):
   if kind=='appsec' and not verified:action='activate'
   else:reason='Bereits installiert und aktiv'
  items.append(dict(name=name,action='skip' if reason else action,reason=reason))
 # Include the full inventory (versions/status), not only displayed names.
 fingerprint=hashlib.sha256(json.dumps({'kind':kind,'managed':managed,'verified':verified,'rows':raw},sort_keys=True,separators=(',',':')).encode()).hexdigest()
 return {'kind':kind,'preview_id':fingerprint,'items':items,'eligible_count':sum(i['action']!='skip'for i in items),'skipped_count':sum(i['action']=='skip'for i in items)}

def recover(control):
 """Called before engine start. Live worker holds flock during intentional reload."""
 STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
 with (STATE/'worker.lock').open('a')as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:
   try:
    owner=json.loads((STATE/'owner.json').read_text())
    if appsec.process_identity(owner['pid'])==owner:return False
   except (OSError,ValueError,KeyError,TypeError,IndexError):pass
   fcntl.flock(lock,fcntl.LOCK_EX)
  restored=False
  job=current();backup=STATE/'recovery-config'
  if job and (job.get('state')in ACTIVE or job.get('recovery_required')):
   if backup.is_dir():
    root=control.CONFIG.parent
    for p in root.iterdir():
     if p.is_dir()and not p.is_symlink():shutil.rmtree(p)
     else:p.unlink()
    shutil.copytree(backup,root,symlinks=True,dirs_exist_ok=True)
    restored=True
   job.update(state='interrupted',recovery_required=False,message='Engine-Neustart: vorherige Konfiguration wiederhergestellt; Vorschau neu laden.')
   for item in job['items']:
    if item['state']!='skipped':item['state']='rolled_back'
   save(job)
  if backup.exists():shutil.rmtree(backup)
  stage=STATE/'recovery-staging'
  if stage.exists():shutil.rmtree(stage)
  (STATE/'owner.json').unlink(missing_ok=True)
  return restored

def start(control,kind,preview_id):
 if kind not in ('scenarios','appsec')or not isinstance(preview_id,str)or not re.fullmatch('[a-f0-9]{64}',preview_id):raise ValueError('Invalid bulk request')
 if not control.LOCK.acquire(blocking=False):raise ValueError('Engine beschäftigt; später erneut versuchen')
 transferred=False
 try:
  if DISABLING.is_set()or CANCELLING.is_set():raise ValueError('AppSec wird deaktiviert; kein neuer Sammelauftrag möglich')
  if (STATE/'recovery-config').exists():raise ValueError('Engine-Wiederherstellung erforderlich; keinen neuen Auftrag starten')
  previous=current()
  if previous and previous.get('preview_id')==preview_id and previous.get('kind')==kind and previous.get('state')in ACTIVE:return previous
  if previous and previous.get('state')in ACTIVE:raise ValueError('Ein Sammelauftrag läuft bereits')
  plan=preview(control,kind)
  if plan['preview_id']!=preview_id:raise ValueError('Katalog geändert; Vorschau neu laden')
  if not plan['eligible_count']:raise ValueError('Keine unterstützten Einträge zu installieren')
  job=dict(id=uuid.uuid4().hex,kind=kind,preview_id=preview_id,state='queued',items=[dict(i,state='skipped'if i['action']=='skip'else'pending')for i in plan['items']],completed=0,total=plan['eligible_count'],message='',created_at=now())
  with STATE_LOCK:
   if DISABLING.is_set()or CANCELLING.is_set():raise ValueError('Deaktivierung läuft; kein neuer Sammelauftrag möglich')
   save(job);CANCEL.clear()
   try:threading.Thread(target=work,args=(control,job,True),daemon=True,name='security-bulk').start()
   except Exception:
    job.update(state='failed',message='Hintergrundauftrag konnte nicht gestartet werden.')
    save(job)
    raise
   transferred=True
  return job
 finally:
  if not transferred:control.LOCK.release()

def work(control,job,release_lock=False):
 try:_work(control,job)
 except Exception:
  job.update(state='failed',recovery_required=(STATE/'recovery-config').exists(),message='Auftrag konnte nicht gestartet werden; Engine-Speicher prüfen.')
  try:save(job)
  except OSError:pass
 finally:
  if release_lock:control.LOCK.release()
  CANCELLING.clear()

def _work(control,job):
 STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
 backup=STATE/'recovery-config';deadline=time.monotonic()+MAX_SECONDS
 with (STATE/'worker.lock').open('a')as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  atomic(STATE/'owner.json',appsec.process_identity(os.getpid()))
  try:
   job.update(state='running');save(job)
   def operation():
    # configuration_transaction has validated snapshot boundaries and size first.
    stage=STATE/'recovery-staging'
    if stage.exists():shutil.rmtree(stage)
    shutil.copytree(control.CONFIG.parent,stage,symlinks=True)
    os.replace(stage,backup)
    for item in job['items']:
     if item['action']=='skip':continue
     if CANCEL.is_set()or time.monotonic()>deadline:raise RuntimeError('Bulk cancelled or deadline reached')
     item['state']='installing';save(job)
     if item['action']=='install':control.invoke(['/usr/bin/cscli','scenarios'if job['kind']=='scenarios'else'appsec-rules','install',item['name']],timeout=min(25,max(1,int(deadline-time.monotonic()))))
     item['state']='staged';job['completed']+=1;save(job)
    job['state']='validating';save(job)
   def validate(_):
    if CANCEL.is_set():raise RuntimeError('Bulk cancelled')
    control.reload_engine()
    rows=appsec.rows(control,'scenarios'if job['kind']=='scenarios'else'appsec-rules');installed={r['name']for r in rows if r['installed']}
    if any(i['name']not in installed for i in job['items']if i['action']!='skip'):raise RuntimeError('Install verification failed')
    if job['kind']=='appsec'and not appsec.runtime_verified(control):raise RuntimeError('AppSec activation not verified')
    if CANCEL.is_set():raise RuntimeError('Bulk cancelled')
    return False
   control.configuration_transaction(operation,reload_required=validate)
   for item in job['items']:
    if item['action']!='skip':item['state']='succeeded'
   job.update(state='succeeded',message='Alle ausgewählten Einträge installiert und Engine geprüft.');save(job)
   if backup.exists():shutil.rmtree(backup)
  except Exception as error:
   # Transaction reports rollback failure explicitly; leave durable recovery copy.
   rollback_failed='rollback failed' in str(error).lower()
   for item in job['items']:
    if item['state']=='installing':item['state']='failed'
    elif item['state']in ('staged','pending'):item['state']='rolled_back'
   job.update(state='failed',recovery_required=rollback_failed,message='Wiederherstellung fehlgeschlagen; Engine prüfen.'if rollback_failed else'Installation fehlgeschlagen; vorherige Konfiguration wiederhergestellt.');save(job)
   if not rollback_failed and backup.exists():shutil.rmtree(backup)
  finally:(STATE/'owner.json').unlink(missing_ok=True)

