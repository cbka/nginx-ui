#!/usr/bin/env python3
import json,os,pathlib
c=json.loads(pathlib.Path('/etc/crowdsec/config.yaml').read_text())
enabled=c['api']['server']['online_client']['sharing']
if type(enabled) is not bool:raise SystemExit('Sharing must be an explicit boolean')
pathlib.Path('/run/crowdsec-mode.json').write_text(json.dumps({'sharing':enabled}))
args=['/usr/local/bin/crowdsec','-c','/etc/crowdsec/config.yaml']
if not enabled:args+=['-no-capi']
os.execv(args[0],args)
