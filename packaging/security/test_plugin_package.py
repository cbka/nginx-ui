import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

class PluginPackageTest(unittest.TestCase):
    def test_package_contains_only_distributables_and_public_certificate(self):
        source = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / 'packaging/security'
            package.mkdir(parents=True)
            shutil.copy(source / 'package-plugin.sh', package / 'package-plugin.sh')
            plugin = root / 'plugins/security-center'
            for path in ('server', 'webapp/dist', 'webapp/node_modules', 'private'):
                (plugin / path).mkdir(parents=True)
            for path in ('README.md', 'LICENSE', 'server/security-center', 'webapp/dist/main.js', 'webapp/dist/style.css'):
                (plugin / path).write_text('asset')
            (plugin / 'plugin.json').write_text('{"version":"0.1.0"}')
            (plugin / 'private/signing.key').write_text('DO-NOT-PACK')
            signing = root / 'signing'
            signing.mkdir(mode=0o700)
            for name in ('primary.pub', 'signing.key', 'plugin.signer', 'plugin.signer.minisig'):
                (signing / name).write_text(name)
            packer = root / 'packer'
            listing = root / 'listing'
            packer.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
if sys.argv[2] == 'pack':
    stage=Path(sys.argv[3])
    Path(os.environ['STAGE_LIST']).write_text('\\n'.join(sorted(str(p.relative_to(stage)) for p in stage.rglob('*') if p.is_file())))
    Path(sys.argv[4]).write_text('archive')
''')
            packer.chmod(0o700)
            env = os.environ | {'PLUGIN_PACKER': str(packer), 'PLUGIN_SIGNING_DIR': str(signing), 'STAGE_LIST': str(listing)}
            subprocess.run(['sh', str(package / 'package-plugin.sh')], env=env, check=True, stdout=subprocess.PIPE)
            self.assertEqual(listing.read_text().splitlines(), ['LICENSE', 'README.md', 'plugin.json', 'plugin.signer', 'plugin.signer.minisig', 'server/security-center', 'webapp/dist/main.js', 'webapp/dist/style.css'])

if __name__ == '__main__':
    unittest.main()
