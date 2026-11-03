#!/usr/bin/env python3
"""Install the signed Security Center package in the isolated lab via normal APIs."""
import argparse
import json
from pathlib import Path
import secrets
import urllib.error
import urllib.request
from bootstrap import Client, LabError, NODES

PLUGIN_ID = 'io.github.mctdatapool.security-center'

def upload(client, archive, public_key):
    data = archive.read_bytes()
    if len(data) > 100 * 1024 * 1024:
        raise LabError('Package exceeds lab upload bound')
    boundary = 'codex-' + secrets.token_hex(20)
    chunks = []
    for key, value in {'author_public_key': public_key, 'enable': 'true'}.items():
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    chunks.extend([
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="security-center.tar.gz"\r\nContent-Type: application/gzip\r\n\r\n'.encode(),
        data, f'\r\n--{boundary}--\r\n'.encode(),
    ])
    headers = client.headers | {'Content-Type': f'multipart/form-data; boundary={boundary}'}
    request = urllib.request.Request(client.base + '/api/plugins', data=b''.join(chunks), headers=headers, method='POST')
    try:
        with client.opener.open(request, timeout=90) as response:
            result = json.loads(response.read(1024 * 1024))
    except urllib.error.HTTPError as error:
        raise LabError(f'{client.name}: plugin upload returned HTTP {error.code}') from None
    if result.get('id') != PLUGIN_ID:
        raise LabError('Unexpected installed plugin identity')
    if not result.get('enabled'):
        result = client.request('POST', f'/plugins/{PLUGIN_ID}/enable', {'approve_permissions': True}, timeout=90)
    if result.get('trust') != 'community' or not result.get('signer'):
        raise LabError('Expected a signed community plugin')
    if result.get('enabled') is not True or result.get('status') != 'running' or result.get('last_error'):
        raise LabError('Installed plugin is not confirmed running')
    return {key: result.get(key) for key in ('id', 'version', 'enabled', 'status', 'trust', 'signer', 'last_error')}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--node', action='append', choices=list(NODES))
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    credentials_path = base / 'state/credentials.json'
    if credentials_path.is_symlink() or credentials_path.stat().st_mode & 0o077:
        raise LabError('Credential file must be private')
    credentials = json.loads(credentials_path.read_text())
    public = (base / 'state/plugin-signing/primary.pub').read_text()
    key = next(line.strip() for line in public.splitlines() if line.strip() and not line.startswith('untrusted comment:'))
    for name in args.node or list(NODES):
        client = Client(name)
        client.login(credentials['nodes'][name], credentials_path, credentials)
        result = upload(client, args.archive, key)
        print(json.dumps({'node': name, **result}), flush=True)

if __name__ == '__main__':
    try:
        main()
    except LabError as error:
        raise SystemExit(str(error)) from None
