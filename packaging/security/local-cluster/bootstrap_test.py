"""Bounded, offline checks for local bootstrap credential handling."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("lab_bootstrap", Path(__file__).with_name("bootstrap.py"))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)

class BootstrapTests(unittest.TestCase):
    def test_totp_rfc6238_six_digits(self):
        self.assertEqual(bootstrap.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59), "287082")

    def test_credentials_private_atomic_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "credentials.json"
            bootstrap.save_credentials(path, {"nodes": {}})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            bootstrap.save_credentials(path, {"nodes": {"node1": {"test": True}}})
            self.assertIn("node1", path.read_text())
            target = Path(root) / "other"
            target.write_text("untouched")
            path.unlink()
            path.symlink_to(target)
            with self.assertRaises(bootstrap.LabError):
                bootstrap.save_credentials(path, {})
            self.assertEqual(target.read_text(), "untouched")

    def test_world_readable_credentials_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "credentials.json"
            path.write_text("{}")
            os.chmod(path, 0o644)
            with self.assertRaises(bootstrap.LabError):
                bootstrap.save_credentials(path, {})

    def test_redirect_refused(self):
        with self.assertRaises(bootstrap.LabError):
            bootstrap.NoRedirect().redirect_request(None, None, None, None, None, None)

if __name__ == "__main__":
    unittest.main()
