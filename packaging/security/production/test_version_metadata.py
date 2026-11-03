import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("version_metadata", Path(__file__).with_name("version_metadata.py"))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class VersionMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = {"version": "3.0.0-security.4", "build_id": 1, "total_build": 581}
        for path in ("app/package.json", "app/src/version.json", "app/dist/version.json"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(self.data))

    def test_matching_built_metadata(self):
        self.assertEqual(metadata.verified_metadata(self.root), self.data)

    def test_stale_source_rejected(self):
        (self.root / "app/src/version.json").write_text(json.dumps({**self.data, "version": "2.9.4"}))
        with self.assertRaises(ValueError):
            metadata.verified_metadata(self.root)

    def test_stale_dist_rejected(self):
        (self.root / "app/dist/version.json").write_text(json.dumps({**self.data, "build_id": 2}))
        with self.assertRaises(ValueError):
            metadata.verified_metadata(self.root)

    def test_prepare_changes_package_not_compiled_output(self):
        metadata.prepare(self.root, "3.0.0-security.5")
        self.assertEqual(json.loads((self.root / "app/package.json").read_text())["version"], "3.0.0-security.5")
        self.assertEqual(json.loads((self.root / "app/dist/version.json").read_text()), self.data)
        with self.assertRaises(ValueError):
            metadata.verified_metadata(self.root)

    def test_invalid_version_rejected(self):
        with self.assertRaises(ValueError):
            metadata.prepare(self.root, '3.0.0"; injected')


if __name__ == "__main__":
    unittest.main()
