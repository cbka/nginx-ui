import http.client
import threading
import time
import unittest
from unittest.mock import patch
from server import BoundedServer, Generator, Handler, PROFILES, TARGETS, send_request, validate


class SafetyTests(unittest.TestCase):
    def test_http_rejects_cross_origin_non_json_and_oversized_commands(self):
        server = BoundedServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for changes, expected in [({'Origin': 'https://evil.example'}, 403), ({'Host': 'evil.example'}, 403), ({'Content-Type': 'text/plain'}, 415), ({'Content-Length': '2048'}, 400)]:
                client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=1)
                headers = {'Host': '127.0.0.1:4184', 'Origin': 'http://127.0.0.1:4184', 'Content-Type': 'application/json', **changes}
                client.request('POST', '/start', '{}', headers)
                self.assertEqual(client.getresponse().status, expected)
                client.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join(1)

    def test_only_fixed_targets_and_paths(self):
        for target in ('example.com', '127.0.0.1', 'node1:443', 'http://node1', 'node1.evil'):
            with self.assertRaises(ValueError):
                send_request(target, '/')
        with self.assertRaises(ValueError):
            send_request('node1', 'http://example.com/')
        with patch('server.http.client.HTTPConnection') as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 302
            self.assertEqual(send_request('node1', '/')[0], '302')
            connection.assert_called_once_with('node1', 80, timeout=2)
            self.assertEqual(connection.return_value.request.call_count, 1)

    def test_limits_and_profiles(self):
        self.assertEqual(validate({}), (1, 60, 'normal', 'all', 16))
        for data in ({'rate': -1}, {'rate': True}, {'rate': float('nan')}, {'rate': 10 ** 400}, {'duration': 10 ** 400}, {'duration': -1}, {'concurrency': 257}, {'concurrency': True}, {'duration': float('inf')}, {'profile': 'arbitrary'}, {'url': 'https://example.com'}, {'target': 'example.com'}, []):
            with self.assertRaises(ValueError):
                validate(data)
        self.assertEqual(validate({'rate': 100000, 'duration': 7200})[:2], (100000, 7200))
        self.assertEqual(validate({'rate': 0, 'duration': 0})[:2], (0, 0))
        for profile in PROFILES:
            self.assertEqual(validate({'profile': profile})[2], profile)

    def test_stop_interrupts_low_rate_wait_and_rejects_overlap(self):
        called = threading.Event()
        generator = Generator(lambda *_: (called.set() or '200', 1))
        generator.start({'rate': .1, 'duration': 300})
        self.assertTrue(called.wait(1))
        with self.assertRaises(ValueError):
            generator.start({})
        started = time.monotonic()
        generator.stop()
        generator.thread.join(0.5)
        self.assertFalse(generator.thread.is_alive())
        self.assertLess(time.monotonic() - started, .5)
        self.assertFalse(generator.snapshot()['running'])

    def test_single_node_selection_is_fixed(self):
        called = threading.Event()
        targets = []
        def sender(target, _path):
            targets.append(target)
            called.set()
            return '200', 1
        generator = Generator(sender)
        generator.start({'target': 'node2'})
        self.assertTrue(called.wait(1))
        generator.stop()
        generator.thread.join(.5)
        self.assertEqual(targets, ['node2'])

    def test_unlimited_mode_has_bounded_inflight_and_no_backlog(self):
        release = threading.Event()
        started = threading.Event()
        calls = []
        def sender(*_):
            calls.append(True)
            if len(calls) == 4:
                started.set()
            release.wait(1)
            return '200', 1
        generator = Generator(sender)
        generator.start({'rate': 0, 'duration': 0, 'concurrency': 4})
        self.assertTrue(started.wait(1))
        time.sleep(.06)
        self.assertEqual(len(calls), 4)
        self.assertLessEqual(generator.snapshot()['peak_inflight'], 4)
        generator.stop()
        release.set()
        generator.thread.join(.5)
        self.assertFalse(generator.thread.is_alive())
        self.assertEqual(len(calls), 4)
        self.assertEqual(generator.snapshot()['inflight'], 0)

    def test_rate_is_global_and_nodes_round_robin(self):
        calls = []
        def sender(target, path):
            calls.append((time.monotonic(), target, path))
            return '403', 2
        generator = Generator(sender)
        generator.start({'rate': 10, 'duration': 1, 'profile': 'mix'})
        generator.thread.join(2)
        self.assertFalse(generator.thread.is_alive())
        self.assertLessEqual(len(calls), 10)
        self.assertGreaterEqual(len(calls), 6)
        self.assertTrue(all(b[0] - a[0] >= .09 for a, b in zip(calls, calls[1:])))
        self.assertEqual([item[1] for item in calls[:3]], list(TARGETS))
        self.assertEqual([item[2] for item in calls[:3]], [PROFILES['mix'][0]] * 3)
        self.assertEqual(sum(item['count'] for item in generator.snapshot()['stats'].values()), len(calls))
        self.assertEqual(generator.log.maxlen, 200)


if __name__ == '__main__':
    unittest.main()
