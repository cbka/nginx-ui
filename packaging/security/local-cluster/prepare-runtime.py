#!/usr/bin/env python3
"""Prepare a fresh isolated lab. Never replace existing persisted state."""
import argparse,json,os,secrets,shutil,subprocess,tempfile
from pathlib import Path
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--engine-binary',required=True);a=p.parse_args()
root=Path(__file__).resolve().parent;state=root/'state'
if state.exists(): raise SystemExit('state already exists; refusing to overwrite persisted lab')
state.mkdir(mode=0o700)
engine=state/'crowdsec';cfg=engine/'config';cfg.mkdir(parents=True)
(engine/'data').mkdir();(cfg/'hub').mkdir();(cfg/'bouncers').mkdir()
# LAPI-only offline lab: explicitly empty local hub, no scenarios installed.
(cfg/'hub/.index.json').write_text('{}\n')
shutil.copy2(a.engine_binary,engine/'engine');os.chmod(engine/'engine',0o755)
password=secrets.token_hex(24);key=secrets.token_hex(24)
secretfile=root/'runtime-secrets.json'
secretfile.write_text(json.dumps({'machine_password':password,'bouncer_key':key}));secretfile.chmod(0o600)
(cfg/'local_api_credentials.yaml').write_text(f'url: http://crowdsec:8080\nlogin: lab-nodes\npassword: {password}\n')
(cfg/'online_api_credentials.yaml').write_text('{}\n')
(cfg/'profiles.yaml').write_text('name: lab\nfilters:\n - Alert.Remediation == true\ndecisions:\n - type: ban\n   duration: 1h\non_success: break\n')
(cfg/'config.yaml').write_text('''common:
 daemonize: false
 log_media: stdout
 log_level: info
config_paths:
 config_dir: /etc/crowdsec
 data_dir: /var/lib/crowdsec/data
 hub_dir: /etc/crowdsec/hub
 index_path: /etc/crowdsec/hub/.index.json
crowdsec_service:
 enable: false
db_config:
 type: sqlite
 db_path: /var/lib/crowdsec/data/crowdsec.db
api:
 client:
  credentials_path: /etc/crowdsec/local_api_credentials.yaml
 server:
  listen_uri: 0.0.0.0:8080
  profiles_path: /etc/crowdsec/profiles.yaml
  online_client:
   credentials_path: /etc/crowdsec/online_api_credentials.yaml
   sharing: false
   pull:
    community: false
    blocklists: false
prometheus:
 enabled: false
''')
(cfg/'bouncers/crowdsec-nginx-bouncer.conf').write_text(f'''ENABLED=true
API_URL=http://crowdsec:8080
API_KEY={key}
MODE=live
CACHE_EXPIRATION=1
BOUNCING_ON_TYPE=all
FALLBACK_REMEDIATION=ban
RET_CODE=403
BAN_TEMPLATE_PATH=/var/lib/crowdsec/lua/templates/ban.html
''')
for f in cfg.rglob('*'):
 if f.is_file():f.chmod(0o600)
container='nginx-security-local-seed'
subprocess.run(['docker','create','--name',container,'--label','codex.task=nginx-security-local-cluster','codex/nginx-ui-security:fork-20261103'],check=True,stdout=subprocess.DEVNULL)
try:
 with tempfile.TemporaryDirectory(prefix='nginx-security-lab-seed-') as temp:
  subprocess.run(['docker','cp',container+':/etc/nginx',temp+'/nginx'],check=True)
  for i in range(1,4):
   node=state/f'node{i}';ui=node/'ui';logs=node/'logs';ui.mkdir(parents=True);logs.mkdir();(logs/'modsecurity').mkdir()
   for name in ['access.log','error.log','security-events.jsonl']:(logs/name).touch()
   shutil.copytree(temp+'/nginx',node/'nginx',symlinks=True)
   nginx=node/'nginx';shutil.copy2(root/'config/nginx.conf',nginx/'nginx.conf')
   for folder in ('conf.d','streams-available','streams-enabled'):(nginx/folder).mkdir(exist_ok=True)
   for existing in (nginx/'sites-enabled').iterdir():existing.unlink()
   shutil.copy2(root/'config/demo.conf',nginx/'sites-available/security-demo.conf')
   (nginx/'sites-enabled/security-demo.conf').symlink_to('/etc/nginx/sites-available/security-demo.conf')
   (nginx/'security-center').mkdir(exist_ok=True)
   shutil.copy2(root.parent/'initial-policy.conf',nginx/'security-center/modsecurity.conf')
   (ui/'app.ini').write_text(f'''[server]
Host = 0.0.0.0
Port = 9000
RunMode = release
[node]
Name = node{i}
Demo = false
[database]
Name = database
[nginx]
ConfigDir = /etc/nginx
ConfigPath = /etc/nginx/nginx.conf
AccessLogPath = /var/log/nginx/access.log
ErrorLogPath = /var/log/nginx/error.log
RestartCmd = /usr/local/sbin/restart.sh
''');(ui/'app.ini').chmod(0o600)
finally:subprocess.run(['docker','rm',container],check=True,stdout=subprocess.DEVNULL)
(state/'loki').mkdir();(state/'alloy').mkdir()
print('Prepared independent node state, engine and local-only credentials. No production configuration copied.')
