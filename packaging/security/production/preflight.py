#!/usr/bin/env python3
"""Test a private copied Nginx configuration without running its application."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import re
import subprocess
import sys
import tempfile
import uuid

MOUNTS = ("/etc/nginx", "/etc/nginx-local", "/var/www")


def host_mappings(path: Path | None) -> list[str]:
    if path is None:
        return []
    mappings = json.loads(path.read_text())
    if not isinstance(mappings, dict) or len(mappings) > 1024:
        raise ValueError("hosts JSON must be an object with at most 1024 entries")
    result = []
    for hostname, address in mappings.items():
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname):
            raise ValueError("invalid hostname in hosts JSON")
        if not isinstance(address, str):
            raise ValueError("host addresses must be IP address strings")
        ip = ipaddress.ip_address(address)
        result += ["--add-host", f"{hostname}={ip}"]
    return result


def inspect_snapshot(root: Path) -> dict:
    links = []
    modules = []
    for destination in MOUNTS:
        source = root / destination.lstrip("/")
        if not source.is_dir() or source.is_symlink():
            raise ValueError(f"snapshot needs a real directory at {destination}")
        for directory, dirs, files in os.walk(source, followlinks=False):
            for name in dirs + files:
                item = Path(directory) / name
                virtual = "/" + str(item.relative_to(root))
                if item.is_symlink():
                    target = os.readlink(item)
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(virtual), target))
                    inside = any(resolved == m or resolved.startswith(m + "/") for m in MOUNTS)
                    links.append({"path": virtual, "target": target,
                                  "resolution": "copied-tree" if inside else "runtime-image"})
                elif item.suffix == ".conf" and item.stat().st_size <= 1024 * 1024:
                    # Report module paths only, never config lines or values.
                    for line in item.read_text(errors="replace").splitlines():
                        match = re.match(r"\s*load_module\s+[\"']?([/A-Za-z0-9_.-]+)[\"']?\s*;", line)
                        if match:
                            modules.append({"config": virtual, "module": match.group(1)})
    if not (root / "etc/nginx/nginx.conf").is_file():
        raise ValueError("snapshot is missing /etc/nginx/nginx.conf")
    return {"symlinks": links, "configured_modules": modules}


def diagnostics(output: str) -> list[dict]:
    """Do not expose raw Nginx output: it can echo credentials/directives."""
    results = []
    kinds = (
        ("host not found", "unresolved host: supply an explicit hosts JSON entry"),
        ("unknown directive", "unsupported or unloaded Nginx module/directive"),
        ("not binary compatible", "dynamic module ABI mismatch"),
        ("dlopen()", "dynamic module load failed"),
        ("cannot load certificate", "certificate unavailable or invalid"),
        ("Permission denied", "file permission denied"),
        ("Read-only file system", "configuration requires a write outside temporary paths"),
        ("No such file or directory", "missing file or unresolved symlink"),
        ("duplicate", "duplicate configuration directive or rule"),
        ("emerg", "Nginx rejected configuration"),
        ("alert", "Nginx alert"),
        ("warn", "Nginx warning"),
    )
    for line in output.splitlines():
        for needle, category in kinds:
            if needle in line:
                record = {"category": category}
                location = re.search(r" in (/[^\s]+):(\d+)(?:\s|$)", line)
                if location:
                    record.update(file=location.group(1), line=int(location.group(2)))
                if record not in results:
                    results.append(record)
                break
    return results or [{"category": "no detailed diagnostic available; raw output withheld"}]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path,
                        help="private root containing etc/nginx, etc/nginx-local, var/www")
    parser.add_argument("--image", required=True, help="already present local image reference")
    parser.add_argument("--hosts", type=Path, help="JSON object mapping DNS names to IP addresses")
    args = parser.parse_args()
    name = "nginx-security-preflight-" + uuid.uuid4().hex[:12]
    started = False
    try:
        root = args.snapshot.resolve(strict=True)
        report = inspect_snapshot(root)
        command = ["docker", "run", "--rm", "--name", name,
                   "--label", "codex.task=nginx-security-production-preflight",
                   "--pull", "never", "--network", "none", "--read-only",
                   "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
                   "--pids-limit", "128", "--security-opt", "no-new-privileges",
                   "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                   "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
                   "--tmpfs", "/var/log/nginx:rw,nosuid,nodev,size=32m",
                   "--tmpfs", "/var/lib/nginx:rw,nosuid,nodev,size=32m",
                   "--tmpfs", "/var/cache/nginx:rw,nosuid,nodev,size=32m"]
        for destination in MOUNTS:
            source = root / destination.lstrip("/")
            if "," in str(source):
                raise ValueError("snapshot path cannot contain commas")
            command += ["--mount", f"type=bind,src={source},dst={destination},readonly"]
        command += host_mappings(args.hosts)
        # No entrypoint, app initialization, daemon, DB access or network sockets.
        command += ["--entrypoint", "/usr/sbin/nginx", args.image,
                    "-t", "-c", "/etc/nginx/nginx.conf", "-e", "stderr"]
        # Disk-backed output prevents large/error-rich configs exhausting RAM.
        with tempfile.TemporaryFile() as output:
            started = True
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=45)
                report["passed"] = result.returncode == 0
                report["exit_code"] = result.returncode
            except subprocess.TimeoutExpired:
                report.update(passed=False, error="45-second preflight timeout")
            output.seek(0)
            raw = output.read(256 * 1024).decode(errors="replace")
        report["diagnostics"] = diagnostics(raw) if not report["passed"] else []
        report["scope"] = "isolated syntax/file compatibility only; no live traffic or application start"
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1
    except (ValueError, OSError, json.JSONDecodeError) as error:
        # Exception text from JSON/files can contain user data; do not echo it.
        print(json.dumps({"passed": False, "error": "invalid inputs or local runtime unavailable",
                          "error_type": type(error).__name__}), file=sys.stderr)
        return 2
    finally:
        if started:
            try:
                cleanup = subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=15, check=False)
                # --rm normally removed it already. A daemon error still requires
                # operator inspection; never delete other task resources.
                if cleanup.returncode not in (0, 1):
                    print(json.dumps({"cleanup_check_required": name}), file=sys.stderr)
            except (OSError, subprocess.TimeoutExpired):
                print(json.dumps({"cleanup_check_required": name}), file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
