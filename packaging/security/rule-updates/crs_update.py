#!/usr/bin/env python3
"""Hourly, authenticated Debian CRS maintenance; never upgrade executable packages."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

STATE = Path(os.getenv('CRS_UPDATE_STATE', '/usr/local/etc/nginx-ui/security-rule-updates/crs'))
LIVE = Path('/usr/share/modsecurity-crs')
KEYRING = '/usr/share/keyrings/debian-archive-keyring.gpg'
INTERVAL = 3600


def run(args, timeout=180, cwd=None):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout, cwd=cwd).stdout


def atomic_json(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    os.replace(temp, path)


def version_line(version):
    match = re.match(r'^(?:\d+:)?(\d+\.\d+)\.', version)
    if not match:
        raise ValueError('Unrecognized package version')
    return match.group(1)


def point(target):
    temp = LIVE.with_name(LIVE.name + '.update-link')
    temp.unlink(missing_ok=True)
    temp.symlink_to(target)
    os.replace(temp, LIVE)


def initialize():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o750)
    if not LIVE.is_symlink():
        # The image copy is immutable fallback; activation only replaces a symlink.
        baseline = LIVE.with_name('modsecurity-crs.image')
        if baseline.exists() and not LIVE.exists():
            LIVE.symlink_to(baseline)
        elif baseline.exists():
            raise RuntimeError('Unexpected existing image fallback')
        else:
            shutil.move(str(LIVE), str(baseline))
            LIVE.symlink_to(baseline)
    initial = STATE / 'baseline.json'
    if not initial.exists():
        version = run(['dpkg-query', '-W', '-f=${Version}', 'modsecurity-crs']).strip()
        atomic_json(initial, {'version': version, 'line': version_line(version)})


def restore():
    initialize()
    marker = STATE / 'active.json'
    if marker.exists():
        active = json.loads(marker.read_text())
        target = STATE / 'releases' / active['sha256'] / 'usr/share/modsecurity-crs'
        if not target.resolve().is_relative_to((STATE / 'releases').resolve()) or not (target / 'rules').is_dir():
            raise RuntimeError('Stored CRS release is unavailable')
        previous = LIVE.resolve()
        point(target)
        try:
            run(['/usr/sbin/nginx', '-t'], 30)
        except Exception:
            point(previous)
            run(['/usr/sbin/nginx', '-t'], 30)
            atomic_json(STATE / 'status.json', {'result': 'restore_failed', 'fallback': 'image', 'checked_at': int(time.time())})
            # A verified image fallback keeps management available for repair.
            marker.rename(STATE / 'rejected-active.json')


def apt_options(work):
    (work / 'lists/partial').mkdir(parents=True)
    (work / 'cache/archives/partial').mkdir(parents=True)
    source = work / 'sources.list'
    source.write_text('\n'.join(
        f'deb [signed-by={KEYRING}] https://{host} {suite} main'
        for host, suite in [('deb.debian.org/debian', 'trixie'),
                            ('deb.debian.org/debian', 'trixie-updates'),
                            ('security.debian.org/debian-security', 'trixie-security')]) + '\n')
    settings = {
        'Dir::Etc::sourcelist': str(source), 'Dir::Etc::sourceparts': '-',
        'Dir::State::lists': str(work / 'lists'), 'Dir::Cache': str(work / 'cache'),
        'APT::Get::List-Cleanup': '0', 'Acquire::Retries': '1',
        'Acquire::http::Timeout': '30', 'Acquire::https::Timeout': '30',
        'APT::Update::Error-Mode': 'any', 'APT::Get::AllowUnauthenticated': 'false',
        'Acquire::AllowInsecureRepositories': 'false', 'APT::Sandbox::User': 'root',
    }
    return [item for key, value in settings.items() for item in ['-o', key + '=' + value]]


def fetch(work, current, line):
    opts = apt_options(work)
    run(['apt-get', *opts, 'update'], 240)
    policy = run(['apt-cache', *opts, 'policy', 'modsecurity-crs'])
    match = re.search(r'^\s*Candidate:\s+(\S+)', policy, re.M)
    if not match or match.group(1) == '(none)':
        raise RuntimeError('No authenticated CRS candidate')
    version = match.group(1)
    if version_line(version) != line:
        raise RuntimeError('CRS major/minor migration requires separate compatibility validation: ' + version)
    newer = subprocess.run(['dpkg', '--compare-versions', version, 'gt', current]).returncode == 0
    if not newer:
        return None
    # Download-only: apt checks the package against signed repository metadata.
    run(['apt-get', *opts, 'download', 'modsecurity-crs=' + version], 240, cwd=work)
    packages = list(work.glob('modsecurity-crs_*.deb'))
    if len(packages) != 1:
        raise RuntimeError('Expected exactly one authenticated CRS package')
    package = packages[0]
    identity = run(['dpkg-deb', '-f', str(package), 'Package', 'Version'])
    if 'Package: modsecurity-crs' not in identity or 'Version: ' + version not in identity:
        raise RuntimeError('CRS package identity mismatch')
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    release = STATE / 'releases' / digest
    if not release.exists():
        stage = STATE / 'releases' / (digest + '.staging')
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        run(['dpkg-deb', '-x', str(package), str(stage)])
        rules = stage / 'usr/share/modsecurity-crs/rules'
        if not list(rules.glob('*.conf')):
            raise RuntimeError('Downloaded CRS has no rule files')
        stage.rename(release)
    return {'version': version, 'sha256': digest, 'source': 'Debian trixie/trixie-security/trixie-updates'}


def activate(candidate):
    previous = LIVE.resolve()
    target = STATE / 'releases' / candidate['sha256'] / 'usr/share/modsecurity-crs'
    point(target)
    try:
        run(['/usr/sbin/nginx', '-t'], 30)
        run(['/usr/sbin/nginx', '-s', 'reload'], 30)
        atomic_json(STATE / 'active.json', candidate)
    except Exception:
        point(previous)
        run(['/usr/sbin/nginx', '-t'], 30)
        run(['/usr/sbin/nginx', '-s', 'reload'], 30)
        raise

    # Retention cleanup must never roll back an already recorded successful apply.
    try:
        # Retain the current and previous releases, plus the image fallback.
        for release in (STATE / 'releases').iterdir():
            tree = release / 'usr/share/modsecurity-crs'
            if release.is_dir() and tree.resolve() not in (target.resolve(), previous):
                shutil.rmtree(release)
    except OSError:
        pass


def check():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o750)
    with (STATE / 'update.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        initialize()
        started = int(time.time())
        base = json.loads((STATE / 'baseline.json').read_text())
        active_file = STATE / 'active.json'
        active = json.loads(active_file.read_text()) if active_file.exists() else base
        status = {'checked_at': started, 'interval_seconds': INTERVAL, 'active_version': active['version']}
        try:
            with tempfile.TemporaryDirectory(prefix='crs-update-') as directory:
                candidate = fetch(Path(directory), active['version'], base['line'])
                if candidate:
                    activate(candidate)
                    status['active_version'] = candidate['version']
            status.update(result='updated' if candidate else 'unchanged', success_at=int(time.time()))
        except Exception as error:
            # Do not emit command output, request data or local configuration.
            status.update(result='failed', error=str(error)[:500])
        atomic_json(STATE / 'status.json', status)
        print(json.dumps(status), flush=True)
        return status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--restore', action='store_true')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if args.restore:
        restore()
    elif args.once:
        result = check()
        if result and result['result'] == 'failed':
            raise SystemExit(1)
    else:
        # Stagger nodes while retaining an hourly maximum check frequency.
        time.sleep(60 + os.getpid() % 30)
        while True:
            check()
            time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
