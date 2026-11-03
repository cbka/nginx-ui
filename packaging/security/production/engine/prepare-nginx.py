#!/usr/bin/env python3
"""Initialize only new Security Center integration files in the green PVC."""
import os,pathlib,shutil
os.umask(0o027)
root=pathlib.Path('/etc/nginx')
policy=root/'plugins-persistent/io.github.mctdatapool.security-center'
policy.mkdir(parents=True,exist_ok=True)
if not (policy/'modsecurity.conf').exists():shutil.copy2('/usr/local/share/nginx-ui-security/initial-policy.conf',policy/'modsecurity.conf')
init=root/'conf.d/00-security-center-init.conf'
content='''# Managed green Security Center runtime; does not attach request hooks to existing sites.
resolver 10.43.0.10 valid=30s ipv6=off;
include /usr/local/share/nginx-ui-security/crowdsec-init.conf;
'''
if init.exists() and init.read_text()!=content:raise SystemExit('Existing Security Center init config differs; refusing overwrite')
init.write_text(content)
site=root/'sites-available/security-integration-test.conf'
if not site.exists():site.write_text('''# Dedicated cluster-internal integration test; port is not published by nginx-public.
server {
 listen 18080;
 server_name security-integration-test.internal;
 set_real_ip_from 127.0.0.1;
 set_real_ip_from 10.42.0.0/16;
 real_ip_header X-Security-Test-IP;
 location / { content_by_lua_block { ngx.say('Security integration test accepted') } }
}
''')
link=root/'sites-enabled/security-integration-test.conf'
if not link.exists():link.symlink_to('/etc/nginx/sites-available/security-integration-test.conf')
pathlib.Path('/var/log/nginx/modsecurity').mkdir(parents=True,exist_ok=True)

# Loopback health checks remain outside managed Security Center site policies.
health = root / "conf.d/00-internal-runtime-health.conf"
health_content = "# Runtime-owned loopback health endpoint; not a managed Security Center site.\n# Specific address takes precedence over the wildcard integration-test listener.\nserver {\n    listen 127.0.0.1:18080;\n    server_name nginx-ui-runtime-health.local;\n    modsecurity off;\n    access_by_lua_block { return }\n    access_log off;\n    location = /healthz { return 200 'ok\\n'; }\n    location / { return 404; }\n}\n"
if health.exists() and health.read_text() != health_content:
    raise SystemExit("Existing internal health config differs; refusing overwrite")
health.write_text(health_content)
