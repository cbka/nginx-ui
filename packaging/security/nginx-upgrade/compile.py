#!/usr/bin/env python3
"""Compile NGINX and every installed dynamic module with identical ABI flags."""
import glob, os, pathlib, shlex, subprocess
root = pathlib.Path('/out')
src = root / 'sources'
subprocess.run(['tar', '-xzf', str(root / 'nginx-1.30.6.tar.gz'), '-C', str(src)], check=True)
nginx = src / 'nginx-1.30.6'
old = subprocess.run(['nginx', '-V'], capture_output=True, text=True, check=True).stderr
args = shlex.split(old.split('configure arguments: ', 1)[1])
args = [a.replace('-Wdate-time', '-Wno-date-time') for a in args if not a.startswith('--add-')]
module_dirs = sorted(src.glob('libnginx-mod-*'))
module_dirs = [p for p in module_dirs if p.is_dir()]
module_dirs.sort(key=lambda p: (0 if 'ndk-' in p.name else 1, p.name))
for module in module_dirs:
    conf = module / 'config'
    if not conf.is_file(): module = module / 'nginx'
    assert (module / 'config').is_file(), module
    args.append('--add-dynamic-module=' + str(module))
env = dict(os.environ, SOURCE_DATE_EPOCH='1790952020', LUAJIT_LIB='/usr/lib/x86_64-linux-gnu', LUAJIT_INC='/usr/include/luajit-2.1')
subprocess.run(['./configure', *args], cwd=nginx, env=env, check=True)
subprocess.run(['make', '-j2'], cwd=nginx, env=env, check=True)
output = root / 'output'
output.mkdir(exist_ok=True)
subprocess.run(['cp', str(nginx/'objs/nginx'), str(output/'nginx')], check=True)
for module in (nginx/'objs').glob('*.so'):
    subprocess.run(['cp', str(module), str(output/module.name)], check=True)
old_names = {p.name for p in pathlib.Path('/usr/lib/nginx/modules').glob('*.so')}
new_names = {p.name for p in output.glob('*.so')}
assert old_names == new_names, (old_names-new_names, new_names-old_names)
print('NGINX 1.30.6: complete module parity', len(new_names))

import shutil
perl = nginx / 'objs/src/http/modules/perl/blib'
shutil.copytree(perl/'lib', output/'perl-lib', dirs_exist_ok=True)
shutil.copytree(perl/'arch/auto', output/'perl-auto', dirs_exist_ok=True)
