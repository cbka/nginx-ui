"""Exercise the real staging script with a fake Docker client; no image build."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class BuildContextTest(unittest.TestCase):
    def test_staging_excludes_lab_state_and_credentials(self):
        source = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix='security-context-test-') as temporary:
            root = Path(temporary)
            package = root/'packaging/security'
            package.mkdir(parents=True)
            shutil.copyfile(source/'build.sh', package/'build.sh')
            # Fixture every package input, plus readable secrets that must NEVER enter context.
            for file in source.iterdir():
                if file.is_file() and file.name != 'build.sh':
                    (package/file.name).write_text('fixture\n')
            (package/'artifacts').mkdir()
            (package/'artifacts/nginx-ui').write_text('fixture binary\n')
            (package/'local-cluster/state/node1').mkdir(parents=True)
            (package/'local-cluster/state/node1/credentials.json').write_text('DO-NOT-COPY')
            (package/'local-cluster/runtime-secrets.json').write_text('DO-NOT-COPY')
            (package/'credentials.json').write_text('DO-NOT-COPY')
            binary = root/'bin'; binary.mkdir()
            docker = binary/'docker'
            docker.write_text('''#!/usr/bin/env python3
import os, pathlib, sys, json
context = pathlib.Path(sys.argv[-1])
files = {str(p.relative_to(context)) for p in context.rglob('*') if p.is_file()}
assert files and 'packaging/security/artifacts/nginx-ui' in files
assert all('local-cluster' not in p and 'secret' not in p and 'credentials' not in p for p in files), files
assert all(p.startswith('packaging/security/') for p in files), files
assert files == set(json.loads(os.environ['EXPECTED_CONTEXT'])), files
pathlib.Path(os.environ['CONTEXT_PROOF']).write_text(str(context))
''')
            docker.chmod(0o755)
            proof = root/'proof'
            expected = {'packaging/security/Dockerfile'}
            for line in (source/'Dockerfile').read_text().splitlines():
                if line.startswith('COPY '):
                    expected.update(line.split()[1:-1])
            env = dict(os.environ, PATH=str(binary)+os.pathsep+os.environ['PATH'],
                       DEBIAN_BASE='debian:trixie-slim@sha256:'+'0'*64,
                       DEBIAN_SNAPSHOT='20261103T000000Z', CONTEXT_PROOF=str(proof),
                       EXPECTED_CONTEXT=json.dumps(sorted(expected)))
            subprocess.run(['sh', str(package/'build.sh')], env=env, check=True)
            self.assertTrue(proof.exists())
            self.assertFalse(Path(proof.read_text()).exists(), 'Staging directory must be removed')


if __name__ == '__main__':
    unittest.main()
