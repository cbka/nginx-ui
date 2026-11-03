#!/usr/bin/env python3
"""Register only this isolated lab's local machine and bouncer; print no secrets."""
import json,subprocess
from pathlib import Path
root=Path(__file__).resolve().parent
marker=root/'state/crowdsec/.registered'
if marker.exists(): raise SystemExit('Local engine already registered; no changes made')
s=json.loads((root/'runtime-secrets.json').read_text())
def run(args):
 result=subprocess.run(['docker','exec','nginx-security-local-crowdsec','cscli',*args],capture_output=True,text=True)
 if result.returncode: raise SystemExit('Local CrowdSec registration failed; inspect configuration privately')
run(['machines','add','lab-nodes','--password',s['machine_password'],'--url','http://crowdsec:8080','--file','/etc/crowdsec/local_api_credentials.yaml'])
run(['bouncers','add','lab-nginx','--key',s['bouncer_key']])
marker.touch()
print('Registered local-only CrowdSec machine and bouncer.')
