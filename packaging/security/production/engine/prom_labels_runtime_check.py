"""Run only inside test-prom-labels.sh's disposable, network-isolated container."""
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

for _ in range(50):
    try:
        with socket.create_connection(('127.0.0.1', 8080), timeout=.2):
            break
    except OSError:
        time.sleep(.1)
else:
    raise AssertionError('isolated fixture LAPI did not start')

stamp = datetime.now(timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')
base = f'192.0.2.1 - - [{stamp}] vhost=example.test server=example.test method=GET status=404 rt=0.1 urt=- bytes=100 '
rid = '0123456789abcdef0123456789abcdef'
# Match fields produced by CrowdSec, not raw input or our own parser reimplementation.
def fields(output, key):
    return re.findall(r'(?:create|update) ' + re.escape(key) + r' : ([^\r\n]*)', output)

def explain(lines):
    Path('/tmp/parser-fixture.log').write_text('\n'.join(base + line for line in lines) + '\n')
    result = subprocess.run(['cscli', 'explain', '-t', 'nginx-prom-labels', '-f', '/tmp/parser-fixture.log', '-v'], capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr[-4000:]
    return result.stdout

cases = [
    (f'request_id={rid} uri=/heartbeat', '/heartbeat', rid),
    (f'uri=/heartbeat request_id={rid}', '/heartbeat', rid),
    ('uri=/heartbeat', '/heartbeat', None),
    (f'request_id={rid} uri=/path%20request_id%3D{rid}', f'/path%20request_id%3D{rid}', rid),
    (f'request_id={rid} uri=/path request_id={rid}', f'/path request_id={rid}', rid),
    ('uri=/path request_id=invalid', '/path request_id=invalid', None),
]
for line, path, request_id in cases:
    out = explain([line])
    assert fields(out, 'evt.Parsed.request') == [path], (line, fields(out, 'evt.Parsed.request'))
    assert fields(out, 'evt.Meta.http_path') == [path], (line, fields(out, 'evt.Meta.http_path'))
    assert fields(out, 'evt.Parsed.request_id') == ([] if request_id is None else [request_id])

for variant in ('prefix', 'suffix'):
    lines = []
    for i in range(12):
        unique_id = f'{i:032x}'
        lines.append(f'request_id={unique_id} uri=/heartbeat' if variant == 'prefix' else f'uri=/heartbeat request_id={unique_id}')
    out = explain(lines)
    paths = fields(out, 'evt.Meta.http_path')
    assert len(paths) == 12 and set(paths) == {'/heartbeat'}, paths
    assert len(set(fields(out, 'evt.Parsed.request_id'))) == 12
    assert set(fields(out, 'evt.Parsed.static_ressource')) == {'false'}

out = explain([f'uri=/favicon.ico request_id={rid}'])
assert fields(out, 'evt.Meta.http_path') == ['/favicon.ico']
assert fields(out, 'evt.Parsed.static_ressource') == ['true']
print('PASS: real CrowdSec prefix/suffix/legacy parsing, literal URI preservation, 12 repeated404 paths remain one distinct path, static resource enrichment')
