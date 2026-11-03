#!/usr/bin/env python3
"""Explicit, isolated lab acceptance: real WAF and CrowdSec on/off/on requests."""
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from bootstrap import Client, LabError, NODES

PLUGIN = 'io.github.mctdatapool.security-center'
BASE = f'/plugins/{PLUGIN}/http/security-center'
REASON = 'security-plugin-lifecycle-acceptance'


def status(node, path='/'):
    request = urllib.request.Request(f'http://127.0.0.1:{8180+node}{path}', headers={'Host': 'security-demo.local'})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def expect(code, path='/'):
    deadline = time.monotonic() + 45
    while True:
        codes = [status(i, path) for i in range(1, 4)]
        if codes == [code] * 3:
            return codes
        if time.monotonic() >= deadline:
            raise LabError(f'Expected {code} on all nodes for {path}: {codes}')
        time.sleep(2)


def decision_ids(value, ip):
    if isinstance(value, list):
        return [item for child in value for item in decision_ids(child, ip)]
    if isinstance(value, dict):
        if value.get('value') == ip and value.get('type') == 'ban' and value.get('id'):
            return [str(value['id'])]
        return [item for child in value.values() for item in decision_ids(child, ip)]
    return []


def main():
    root = Path(__file__).resolve().parent
    path = root / 'state/credentials.json'
    credentials = json.loads(path.read_text())
    clients = []
    for name in NODES:
        client = Client(name)
        client.login(credentials['nodes'][name], path, credentials)
        clients.append(client)
    ip = subprocess.check_output(['docker', 'inspect', 'nginx-security-local-gateway', '--format', '{{(index .NetworkSettings.Networks "nginx-security-local-lab").IPAddress}}'], text=True).strip()
    policies = [c.request('GET', BASE + '/sites/security-demo.conf') for c in clients]
    if decision_ids(clients[0].request('GET', BASE + '/crowdsec/decisions'), ip):
        raise LabError('Gateway already has a ban; refusing to alter existing decisions')
    ids = []
    ban_created = False
    try:
        print(json.dumps({'normal': expect(200), 'waf_enabled': expect(403, '/.env')}), flush=True)
        clients[0].request('POST', BASE + '/crowdsec/decisions', {'ip': ip, 'duration': '5m', 'reason': REASON})
        ban_created = True
        ids = decision_ids(clients[0].request('GET', BASE + '/crowdsec/decisions'), ip)
        if not ids:
            raise LabError('Test ban ID not returned')
        print(json.dumps({'crowdsec_enabled': expect(403)}), flush=True)
        for client in clients:
            client.request('POST', f'/plugins/{PLUGIN}/disable', {}, timeout=60)
        print(json.dumps({'crowdsec_disabled': expect(200), 'waf_disabled': expect(200, '/.env')}), flush=True)
        for client in clients:
            client.request('POST', f'/plugins/{PLUGIN}/enable', {'approve_permissions': True}, timeout=60)
        print(json.dumps({'crowdsec_reenabled': expect(403)}), flush=True)
        for decision in ids:
            clients[0].request('DELETE', BASE + '/crowdsec/decisions/' + decision)
        ids = []
        ban_created = False
        print(json.dumps({'normal_restored': expect(200), 'waf_reenabled': expect(403, '/.env')}), flush=True)
        after = [c.request('GET', BASE + '/sites/security-demo.conf') for c in clients]
        if policies != after:
            raise LabError('Policy metadata changed across lifecycle')
        print(json.dumps({'policies_preserved': True, 'test_bans_removed': True, 'nodes': 3}), flush=True)
    finally:
        for client in clients:
            client.request('POST', f'/plugins/{PLUGIN}/enable', {'approve_permissions': True}, timeout=60)
        if ban_created:
            for decision in ids or decision_ids(clients[0].request('GET', BASE + '/crowdsec/decisions'), ip):
                clients[0].request('DELETE', BASE + '/crowdsec/decisions/' + decision)


if __name__ == '__main__':
    main()
