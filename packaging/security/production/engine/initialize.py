#!/usr/bin/env python3
"""Seed only a new persistent engine. Credentials are projected private files."""
import json,os,pathlib,shutil,subprocess
os.umask(0o077)
cfg=pathlib.Path('/etc/crowdsec');data=pathlib.Path('/var/lib/crowdsec/data');marker=data/'.nginx-security-initialized'
if marker.exists():raise SystemExit(0)
cfg.mkdir(parents=True,exist_ok=True);data.mkdir(parents=True,exist_ok=True)
if (data/'crowdsec.db').exists():raise SystemExit('Existing unmarked engine database: manual reconciliation required')
shutil.copytree('/usr/share/nginx-security-engine/config',cfg,dirs_exist_ok=True,symlinks=True)
shutil.copytree('/usr/share/nginx-security-engine/data',data,dirs_exist_ok=True,symlinks=True)
base=json.loads(pathlib.Path('/engine-defaults/config.json').read_text())
if base['api']['server']['online_client']['sharing'] is not False:raise SystemExit('Initial sharing must be disabled')
(cfg/'config.yaml').write_text(json.dumps(base,indent=2))
for name in ['acquis.yaml','profiles.yaml']:
 shutil.copy2('/engine-defaults/'+name,cfg/name)
shutil.copy2('/engine-defaults/nginx-prom-labels-parser.yaml',cfg/'parsers/s01-parse/nginx-prom-labels.yaml')
(cfg/'online_api_credentials.yaml').write_text('{}\n')
password=pathlib.Path('/run/secrets/machine-password').read_text().strip()
key=pathlib.Path('/run/secrets/bouncer-key').read_text().strip()
for command in [['machines','add','nginx-security-engine','--password',password,'--url','http://127.0.0.1:8080','--file',str(cfg/'local_api_credentials.yaml')],['bouncers','add','nginx-fork','--key',key]]:
 r=subprocess.run(['/usr/bin/cscli',*command],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=20)
 if r.returncode:raise SystemExit('Engine credential registration failed; initialized marker not written')
marker.touch(mode=0o600)
