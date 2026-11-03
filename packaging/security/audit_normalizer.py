#!/usr/bin/env python3
"""Normalize security events before shipping: no raw payload/header/query values.

A filter, not a log-tail service. Run behind a rotation/checkpoint-aware reader.
Node and vhost are trusted collector metadata, never taken from request headers.
"""
import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_LINE = 1024 * 1024
RULE_MESSAGES = {
    200002: "Request body could not be parsed",
    200003: "Multipart body failed validation",
    200004: "Multipart boundary failed validation",
    200007: "Request argument limit exceeded",
    200008: "Request body exceeds inspection limit",
    941100: "XSS pattern detected by libinjection",
    942100: "SQL injection pattern detected by libinjection",
    949110: "Inbound anomaly score threshold exceeded",
    959100: "Outbound anomaly score threshold exceeded",
}


def clean(value, maximum=256):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(value or ""))[:maximum]


def client_ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return ""


def safe_path(value):
    try:
        path = urlsplit(str(value)).path
        return clean(path, 2048) if path.startswith("/") else ""
    except ValueError:
        return ""


def event_time(value):
    value = str(value or "")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return ""
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        try:
            # Runtime TZ is explicitly UTC; ModSecurity omits the timezone.
            parsed = datetime.strptime(value, "%a %b %d %H:%M:%S %Y")
            return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            return ""


def identity(source, node, transaction, index):
    return hashlib.sha256(f"{source}\0{node}\0{transaction}\0{index}".encode()).hexdigest()


def modsecurity(document, node, vhost=""):
    tx = document.get("transaction", {})
    if not isinstance(tx, dict):
        return []
    req = tx.get("request", {})
    response = tx.get("response", {})
    producer = tx.get("producer", {})
    if not all(isinstance(x, dict) for x in [req, response, producer]):
        return []
    transaction = clean(tx.get("unique_id"))
    messages = tx.get("messages", [])
    if not transaction or not isinstance(messages, list):
        return []
    result = []
    for index, item in enumerate(messages[:200]):
        if not isinstance(item, dict) or not isinstance(item.get("details"), dict):
            continue
        detail = item["details"]
        try:
            rule_id = int(detail.get("ruleId", 0))
        except (ValueError, TypeError):
            continue
        if rule_id <= 0:
            continue
        # Only a variable name, never the matched value or arbitrary rule message.
        match = re.search(r"against variable `((?:ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS):[A-Za-z0-9_.\[\]-]{1,100})'", str(detail.get("match", "")))
        engine = producer.get("secrules_engine", "")
        status = response.get("http_code", 0)
        action = "detected" if engine == "DetectionOnly" else "matched"
        # HTTP status alone is not proof of a disruptive ModSecurity intervention.
        # 949110 and baseline deny rules are known disruptive rules in this runtime.
        if engine == "Enabled" and status in [400, 403, 413] and rule_id in [200002, 200003, 200004, 200007, 200008, 949110, 959100]:
            action = "blocked"
        result.append({
            "source": "modsecurity", "vhost": clean(vhost), "node": clean(node),
            "event_time": event_time(tx.get("time_stamp")),
            "event_id": identity("modsecurity", node, transaction, index),
            "rule_id": rule_id, "scenario": "", "message": RULE_MESSAGES.get(rule_id, f"ModSecurity rule {rule_id} matched"),
            "method": clean(req.get("method"), 16), "path": safe_path(req.get("uri", "")),
            "parameter": match.group(1) if match else "", "client_ip": client_ip(tx.get("client_ip")),
            "action": action, "transaction_id": transaction,
        })
    return result


# Parse only the known bouncer denial format, not arbitrary Nginx errors.
BOUNCER = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[alert\].*?\[lua\] crowdsec\.lua:\d+: Allow\(\): \[Crowdsec\] denied '[^']+' with '(ban|captcha)' \(by bouncer\), client: ([^,]+), server: ([^,]*), request: \"([A-Z]+) ([^\"]*) HTTP/[^\"]+\"")


def crowdsec(line, node, vhost=""):
    found = BOUNCER.search(line)
    if not found:
        return []
    kind, address, _configured_server, method, target = found.groups()
    # Caller may pass vhost only after resolving configured server to a site;
    # aliases and empty server_name must not be invented from Host headers.
    event_id = hashlib.sha256((node + "\0" + line).encode()).hexdigest()
    return [{"source": "crowdsec", "vhost": clean(vhost), "node": clean(node),
             "event_id": event_id, "rule_id": 0, "scenario": "",
             "message": "CrowdSec remediation enforced", "method": clean(method, 16),
             "path": safe_path(target), "parameter": "", "client_ip": client_ip(address),
             "action": kind, "transaction_id": ""}]


def site_identity(audit_file, policy_dir):
    # Filename hash binds metadata name to generated policy, not a client header.
    name = Path(audit_file).name
    if not re.fullmatch(r"[a-f0-9]{64}\.json", name):
        raise ValueError("audit file must use a generated site hash")
    data = json.loads((Path(policy_dir) / name).read_text())
    site = data.get("name")
    if not isinstance(site, str) or hashlib.sha256(site.encode()).hexdigest() + ".json" != name:
        raise ValueError("site metadata hash mismatch")
    return site



# A source-local structured hook, distinct from central CrowdSec engine alerts.
STRUCTURED = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[warn\].*?\[lua\] nginx_ui_security_events\.lua:\d+: emit\(\): NGINX_UI_SECURITY_EVENT ")


def structured_crowdsec(line, node, policy_dir):
    found = STRUCTURED.match(line)
    if not found:
        return []
    try:
        # Ignore Nginx's appended request/header context after the JSON object.
        data, _ = json.JSONDecoder().raw_decode(line[found.end():])
        site_id = data.get("site_id", "")
        vhost = site_identity(site_id + ".json", policy_dir) if site_id else ""
        transaction = clean(data.get("transaction_id"))
        action = data.get("action")
        timestamp = event_time(data.get("event_time"))
        if action not in ["ban", "captcha", "challenge"] or not transaction or not timestamp:
            return []
        return [{"source": "crowdsec", "vhost": clean(vhost), "node": clean(node),
                 "event_time": timestamp, "event_id": identity("crowdsec", node, transaction, action),
                 "rule_id": 0, "scenario": "", "message": "CrowdSec remediation enforced",
                 "method": clean(data.get("method"), 16), "path": safe_path(data.get("path", "")),
                 "parameter": "", "client_ip": client_ip(data.get("client_ip")),
                 "action": action, "transaction_id": transaction}]
    except (ValueError, TypeError, AttributeError, FileNotFoundError):
        return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["modsecurity", "crowdsec"], required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--audit-file")
    parser.add_argument("--policy-dir", default="/etc/nginx/security-center/sites")
    args = parser.parse_args()
    vhost = site_identity(args.audit_file, args.policy_dir) if args.audit_file else ""
    while line := sys.stdin.readline(MAX_LINE + 1):
        if len(line) > MAX_LINE:
            while line and not line.endswith("\n"):
                line = sys.stdin.readline(MAX_LINE + 1)
            print("security event discarded: size limit", file=sys.stderr)
            continue
        try:
            records = modsecurity(json.loads(line), args.node, vhost) if args.source == "modsecurity" else structured_crowdsec(line, args.node, args.policy_dir)
            for record in records:
                print(json.dumps(record, separators=(",", ":")), flush=True)
        except (ValueError, TypeError, AttributeError):
            print("security event discarded: invalid format", file=sys.stderr)


if __name__ == "__main__":
    main()
