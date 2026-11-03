import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('updater', Path(__file__).with_name('crs_update.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state = root / 'state'
        self.state.mkdir()
        self.live = root / 'crs'
        self.old = root / 'old'
        self.old.mkdir()
        self.live.symlink_to(self.old)
        self.new = self.state / 'releases/abc/usr/share/modsecurity-crs'
        (self.new / 'rules').mkdir(parents=True)
        self.candidate = {'version': '3.3.8-1', 'sha256': 'abc'}
        for name, val in [('STATE', self.state), ('LIVE', self.live)]:
            p = patch.object(u, name, val)
            p.start()
            self.addCleanup(p.stop)

    def test_interrupted_initial_conversion_recovers(self):
        self.live.unlink()
        baseline = self.live.with_name('modsecurity-crs.image')
        baseline.mkdir()
        with patch.object(u, 'run', return_value='3.3.7-1'):
            u.initialize()
        self.assertEqual(self.live.resolve(), baseline)

    def test_failed_restore_uses_validated_image_fallback(self):
        (self.state / 'active.json').write_text(json.dumps(self.candidate))
        with patch.object(u, 'initialize'), patch.object(u, 'run', side_effect=[RuntimeError('bad restored rules'), '']):
            u.restore()
        self.assertEqual(self.live.resolve(), self.old)
        self.assertFalse((self.state / 'active.json').exists())
        self.assertTrue((self.state / 'rejected-active.json').exists())

    def test_activation_records_only_after_test_and_reload(self):
        with patch.object(u, 'run', return_value='') as run:
            u.activate(self.candidate)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(self.live.resolve(), self.new)
        self.assertEqual(json.loads((self.state / 'active.json').read_text()), self.candidate)

    def test_failed_test_restores_previous_and_does_not_record(self):
        with patch.object(u, 'run', side_effect=[RuntimeError('bad rules'), '', '']):
            with self.assertRaises(RuntimeError):
                u.activate(self.candidate)
        self.assertEqual(self.live.resolve(), self.old)
        self.assertFalse((self.state / 'active.json').exists())

    def test_failed_reload_restores_previous(self):
        with patch.object(u, 'run', side_effect=['', RuntimeError('reload'), '', '']):
            with self.assertRaises(RuntimeError):
                u.activate(self.candidate)
        self.assertEqual(self.live.resolve(), self.old)

    def test_major_migration_rejected_before_download(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(u, 'run', side_effect=['', 'Candidate: 4.25.0-1\n']) as run:
                with self.assertRaisesRegex(RuntimeError, 'migration'):
                    u.fetch(Path(temp), '3.3.7-1', '3.3')
                self.assertEqual(run.call_count, 2)

    def test_apt_sources_require_signature_and_are_isolated(self):
        with tempfile.TemporaryDirectory() as temp:
            opts = u.apt_options(Path(temp))
            self.assertIn('APT::Get::AllowUnauthenticated=false', opts)
            self.assertIn('Acquire::AllowInsecureRepositories=false', opts)
            self.assertIn('signed-by=', (Path(temp) / 'sources.list').read_text())

    def test_unchanged_version_never_reloads(self):
        (self.state / 'baseline.json').write_text(json.dumps({'version': '3.3.7-1', 'line': '3.3'}))
        with patch.object(u, 'initialize'), patch.object(u, 'fetch', return_value=None), patch.object(u, 'activate') as activate:
            result = u.check()
            self.assertEqual(result['result'], 'unchanged')
            activate.assert_not_called()

    def test_failure_keeps_active_version_in_status(self):
        (self.state / 'baseline.json').write_text(json.dumps({'version': '3.3.7-1', 'line': '3.3'}))
        with patch.object(u, 'initialize'), patch.object(u, 'fetch', side_effect=RuntimeError('offline')):
            result = u.check()
            self.assertEqual(result['result'], 'failed')
            self.assertEqual(result['active_version'], '3.3.7-1')

if __name__ == '__main__':
    unittest.main()
