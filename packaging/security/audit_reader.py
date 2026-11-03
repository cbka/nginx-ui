#!/usr/bin/env python3
"""Bounded, at-least-once source-local audit normalization; no raw log shipping."""
import fcntl
import hashlib
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from audit_normalizer import MAX_LINE, modsecurity, site_identity, structured_crowdsec

MAX_FILES = 256
MAX_CYCLE_BYTES = 8 * 1024 * 1024
NAME = re.compile(r"^([a-f0-9]{64}\.json)(?:\.[0-9]+)?$")


class Reader:
    def __init__(self, audit_dir, policy_dir, output, state_file, node, error_log=None):
        self.audit_dir, self.policy_dir = Path(audit_dir), Path(policy_dir)
        self.output, self.state_file, self.node = Path(output), Path(state_file), node
        self.error_log = Path(error_log) if error_log else None
        self.state = {}
        # A crash can leave a partial final JSONL record. Remove that fragment
        # before replay; otherwise it would concatenate with the first replayed event.
        if self.output.exists():
            fd = os.open(self.output, os.O_RDWR | os.O_NOFOLLOW)
            with os.fdopen(fd, "r+b") as output:
                size = output.seek(0, os.SEEK_END)
                output.seek(max(0, size - MAX_LINE))
                tail = output.read()
                if tail and not tail.endswith(b"\n"):
                    boundary = tail.rfind(b"\n")
                    output.truncate(max(0, size - len(tail) + boundary + 1))
                    output.flush()
                    os.fsync(output.fileno())
        if self.state_file.exists():
            # Fail rather than silently replay/lose position on a corrupt checkpoint.
            self.state = json.loads(self.state_file.read_text())
            if not isinstance(self.state, dict):
                raise ValueError("invalid audit checkpoint")

    def checkpoint(self):
        self.state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = self.state_file.with_suffix(".tmp")
        with open(temp, "w") as file:
            os.chmod(temp, 0o600)
            json.dump(self.state, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, self.state_file)
        fd = os.open(self.state_file.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def scan(self):
        candidates = []
        for path in self.audit_dir.glob("*.json*"):
            matched = NAME.fullmatch(path.name)
            if matched and path.is_file() and not path.is_symlink():
                candidates.append((path.stat().st_mtime_ns, path, matched.group(1)))
        if self.error_log:
            for path in self.error_log.parent.glob(self.error_log.name + "*"):
                if re.fullmatch(re.escape(self.error_log.name) + r"(?:\.[0-9]+)?", path.name) and path.is_file() and not path.is_symlink():
                    candidates.append((path.stat().st_mtime_ns, path, None))
        # Explicit failure rather than silently ignoring protection events.
        if len(candidates) > MAX_FILES:
            raise RuntimeError("audit source file limit exceeded; rotate/remove archived files")
        consumed = 0
        seen = set()
        for _, path, metadata_name in sorted(candidates):
            if consumed >= MAX_CYCLE_BYTES:
                break
            vhost = ""
            if metadata_name:
                metadata = self.policy_dir / metadata_name
                if metadata.is_symlink():
                    raise ValueError("audit metadata symlink rejected")
                try:
                    vhost = site_identity(metadata_name, self.policy_dir)
                except FileNotFoundError:
                    # Wait for matching server-owned metadata; never guess from Host.
                    continue
            try:
                file = open(path, "rb")
            except FileNotFoundError:  # rotated between discovery and open
                continue
            with file:
                stat = os.fstat(file.fileno())
                key = f"{stat.st_dev}:{stat.st_ino}"
                if key in seen:
                    continue
                seen.add(key)
                old = self.state.get(key, {})
                prefix_len = old.get("prefix_len", min(64, stat.st_size))
                prefix = hashlib.sha256(file.read(prefix_len)).hexdigest()
                offset = old.get("offset", 0)
                if offset > stat.st_size or (old and prefix != old.get("prefix")):
                    offset = 0
                    prefix_len = min(64, stat.st_size)
                    file.seek(0)
                    prefix = hashlib.sha256(file.read(prefix_len)).hexdigest()
                file.seek(offset)
                discarding = old.get("discarding", False) if offset else False
                while consumed < MAX_CYCLE_BYTES:
                    start = file.tell()
                    line = file.readline(MAX_LINE + 1)
                    if not line:
                        break
                    if not discarding and not line.endswith(b"\n") and len(line) <= MAX_LINE:
                        file.seek(start)  # wait for complete JSON record
                        break
                    consumed += len(line)
                    if discarding or len(line) > MAX_LINE:
                        # Continue discarding across polls/checkpoints without unbounded I/O.
                        if not discarding:
                            print("security audit record discarded: size limit", file=sys.stderr)
                        discarding = not line.endswith(b"\n")
                        records = []
                    else:
                        try:
                            records = modsecurity(json.loads(line), self.node, vhost) if metadata_name else structured_crowdsec(line.decode("utf-8", "replace"), self.node, self.policy_dir)
                        except (ValueError, TypeError, AttributeError, RecursionError):
                            records = []
                            print("security audit record discarded: invalid JSON", file=sys.stderr)
                    if records:
                        # Open on each batch so normal output rename-rotation is respected.
                        self.output.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
                        fd = os.open(self.output, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
                        with os.fdopen(fd, "w") as output:
                            for row in records:
                                output.write(json.dumps(row, separators=(",", ":")) + "\n")
                            output.flush()
                            os.fsync(output.fileno())
                    # Output durable first. Crash before checkpoint may replay, same event_id.
                    self.state[key] = {"offset": file.tell(), "prefix": prefix, "prefix_len": prefix_len, "discarding": discarding}
                # One checkpoint per file; stable IDs allow consumer dedup after crash.
                self.checkpoint()
        if consumed < MAX_CYCLE_BYTES:
            self.state = {key: value for key, value in self.state.items() if key in seen}
            self.checkpoint()
        return consumed


def main():
    if os.environ.get("NGINX_UI_SECURITY_AUDIT_ENABLED") != "true":
        print("Security audit reader disabled; set NGINX_UI_SECURITY_AUDIT_ENABLED=true after configuring per-site audit files")
        return
    node = os.environ.get("NODE_NAME", "")
    if not node:
        raise ValueError("NODE_NAME must be injected by the trusted runtime")
    state = Path("/usr/local/etc/nginx-ui/security-audit-state/cursors.json")
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # One owner per cursor/output stream; other instances fail instead of racing.
    lock = open(state.parent / "reader.lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    reader = Reader("/var/log/nginx/modsecurity", "/etc/nginx/security-center/sites",
                    "/var/log/nginx/security-events.jsonl", state, node, "/var/log/nginx/error.log")
    running = True
    def stop(_signum, _frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        reader.scan()
        time.sleep(1)


if __name__ == "__main__":
    os.umask(0o027)
    main()
