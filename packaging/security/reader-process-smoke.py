#!/usr/bin/env python3
"""Run only in an isolated disposable runtime container; uses production paths."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

name = "smoke-site.conf"
identity = hashlib.sha256(name.encode()).hexdigest()
audit = Path("/var/log/nginx/modsecurity")
policy = Path("/etc/nginx/security-center/sites")
audit.mkdir(parents=True, exist_ok=True)
policy.mkdir(parents=True, exist_ok=True)
(policy / (identity + ".json")).write_text(json.dumps({"name": name}))
source = audit / (identity + ".json")
output = Path("/var/log/nginx/security-events.jsonl")

def record(key):
    return json.dumps({"transaction": {"unique_id": key, "request": {"uri": "/test?token=do-not-ship"}, "response": {}, "producer": {}, "messages": [{"details": {"ruleId": "941100"}}]}}) + "\n"

def start():
    return subprocess.Popen(["python3", "/usr/local/lib/nginx-ui-security/audit_reader.py"], env={**os.environ, "NODE_NAME": "smoke-node", "NGINX_UI_SECURITY_AUDIT_ENABLED": "true"})

def wait_rows(count):
    for _ in range(30):
        if output.exists():
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            if len(rows) == count:
                return rows
        time.sleep(0.1)
    raise AssertionError("reader output count not reached")

source.write_text(record("first"))
process = start()
try:
    rows = wait_rows(1)
    assert rows[0]["node"] == "smoke-node" and rows[0]["vhost"] == name
    assert "do-not-ship" not in output.read_text()
finally:
    process.terminate(); process.wait(timeout=5)
with source.open("a") as file:
    file.write(record("second"))
process = start()
try:
    rows = wait_rows(2)
    assert [row["transaction_id"] for row in rows] == ["first", "second"]
finally:
    process.terminate(); process.wait(timeout=5)
print("PASS: real reader process normalizes source, preserves cursor across restart, exits on SIGTERM")
