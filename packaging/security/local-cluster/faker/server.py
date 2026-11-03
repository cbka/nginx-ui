"""Bounded local test traffic. Targets and payloads are intentionally not configurable."""
import collections
import http.client
import json
import math
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

TARGETS = ('node1', 'node2', 'node3')
PROFILES = {
    'normal': ('/', '/?q=hello'),
    'sql-injection': ('/?id=1%20UNION%20SELECT%20password%20FROM%20users',),
    'xss': ('/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E',),
    'scanner': ('/wp-login.php', '/.env', '/phpmyadmin/', '/admin/login'),
}
PROFILES['mix'] = sum(PROFILES.values(), ())


def validate(data):
    if not isinstance(data, dict) or set(data) - {'rate', 'duration', 'profile', 'target'}:
        raise ValueError('Only rate, duration, profile and target are accepted')
    rate = data.get('rate', 1)
    duration = data.get('duration', 60)
    profile = data.get('profile', 'normal')
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or not 0.1 <= rate <= 20:
        raise ValueError('Rate must be between 0.1 and 20 requests/second')
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or not 1 <= duration <= 300:
        raise ValueError('Duration must be between 1 and 300 seconds')
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError('Unknown profile')
    target = data.get('target', 'all')
    if target not in ('all', *TARGETS):
        raise ValueError('Unknown fixed target')
    return rate, duration, profile, target


def send_request(target, path):
    if target not in TARGETS or path not in PROFILES['mix']:
        raise ValueError('Target or payload is not allowlisted')
    connection = http.client.HTTPConnection(target, 80, timeout=2)
    start = time.monotonic()
    try:
        connection.request('GET', path, headers={'Host': 'security-demo.local', 'User-Agent': 'nginx-ui-local-faker/1.0', 'Connection': 'close'})
        response = connection.getresponse()
        # Do not follow redirects or retain response content / request credentials.
        status = str(response.status)
        response.read(4096)
        return status, round((time.monotonic() - start) * 1000, 1)
    except (OSError, http.client.HTTPException):
        return 'network-error', round((time.monotonic() - start) * 1000, 1)
    finally:
        connection.close()


class Generator:
    def __init__(self, sender=send_request):
        self.sender = sender
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None
        self.running = False
        self.log = collections.deque(maxlen=200)
        self.stats = {}
        self.config = {}

    def start(self, data):
        rate, duration, profile, target = validate(data)
        with self.lock:
            if self.running:
                raise ValueError('A test is already running')
            self.running = True
            self.stop_event.clear()
            self.log.clear()
            self.stats = {node: {'count': 0, 'status': {}, 'latency_total': 0, 'latency_max': 0} for node in TARGETS}
            self.config = {'rate': rate, 'duration': duration, 'profile': profile, 'target': target}
            self.thread = threading.Thread(target=self.run, args=(rate, duration, profile, target), daemon=True)
            self.thread.start()

    def run(self, rate, duration, profile, target):
        targets = TARGETS if target == 'all' else (target,)
        deadline = time.monotonic() + duration
        index = 0
        try:
            while not self.stop_event.is_set() and time.monotonic() < deadline:
                started = time.monotonic()
                target = targets[index % len(targets)]
                paths = PROFILES[profile]
                # Every node receives every profile payload across cycles.
                path = paths[(index // len(targets)) % len(paths)]
                status, latency = self.sender(target, path)
                with self.lock:
                    entry = self.stats[target]
                    entry['count'] += 1
                    entry['status'][status] = entry['status'].get(status, 0) + 1
                    entry['latency_total'] += latency
                    entry['latency_max'] = max(entry['latency_max'], latency)
                    self.log.append({'time': time.strftime('%H:%M:%S'), 'node': target, 'path': path, 'status': status, 'latency_ms': latency})
                index += 1
                # No catch-up bursts after slow requests. Limit is global, not per node.
                self.stop_event.wait(max(0, min(deadline - time.monotonic(), 1 / rate - (time.monotonic() - started))))
        finally:
            with self.lock:
                self.running = False

    def stop(self):
        self.stop_event.set()

    def snapshot(self):
        with self.lock:
            stats = {node: {**entry, 'status': dict(entry['status']), 'latency_avg': round(entry['latency_total'] / max(1, entry['count']), 1)} for node, entry in self.stats.items()}
            return {'running': self.running, 'config': dict(self.config), 'stats': stats, 'log': list(reversed(self.log)), 'targets': list(TARGETS)}


GENERATOR = Generator()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def reply(self, code, data, content_type='application/json'):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/status':
            self.reply(200, GENERATOR.snapshot())
        elif self.path in ('/', '/app.js', '/style.css'):
            name, content_type = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}[self.path]
            self.reply(200, Path(__file__).with_name(name).read_bytes(), content_type)
        else:
            self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        if self.headers.get('Host') not in ('127.0.0.1:4184', 'localhost:4184', '[::1]:4184', 'faker:4184'):
            return self.reply(403, {'error': 'Unexpected host'})
        origin = self.headers.get('Origin')
        if origin and urlsplit(origin).netloc != self.headers.get('Host'):
            return self.reply(403, {'error': 'Cross-origin commands are not allowed'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.reply(415, {'error': 'JSON required'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 1024:
                raise ValueError('Body must be 1..1024 bytes')
            data = json.loads(self.rfile.read(length))
            if self.path == '/start':
                GENERATOR.start(data)
            elif self.path == '/stop':
                GENERATOR.stop()
            else:
                return self.reply(404, {'error': 'Not found'})
            self.reply(200, GENERATOR.snapshot())
        except (ValueError, TimeoutError):
            self.reply(400, {'error': 'Invalid request or limits; rate 0.1–20/s, duration 1–300s, known profile; no overlapping runs'})

    def log_message(self, *_args):
        pass


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    slots = threading.BoundedSemaphore(6)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


if __name__ == '__main__':
    BoundedServer(('0.0.0.0', 4184), Handler).serve_forever()
